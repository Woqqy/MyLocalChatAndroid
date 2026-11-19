package com.mychat.app

import android.app.Activity
import android.os.Bundle
import android.webkit.*
import android.view.View
import android.widget.*
import android.graphics.Color
import android.graphics.Typeface
import android.view.Gravity
import android.view.WindowManager
import fi.iki.elonen.NanoHTTPD
import org.json.JSONObject
import org.json.JSONArray
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec
import java.util.concurrent.ConcurrentHashMap

class MainActivity : Activity() {
    private lateinit var server: ChatServer
    private lateinit var web: WebView
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.statusBarColor = Color.rgb(14,22,33); window.navigationBarColor = Color.rgb(14,22,33)
        window.setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_ADJUST_RESIZE)
        server = ChatServer(this).also { it.start(NanoHTTPD.SOCKET_READ_TIMEOUT, false) }
        web = WebView(this)
        web.settings.javaScriptEnabled = true
        web.settings.domStorageEnabled = true
        web.settings.allowFileAccess = true
        web.webViewClient = WebViewClient()
        web.setBackgroundColor(Color.rgb(14,22,33))
        setContentView(web)
        web.loadUrl("http://127.0.0.1:8765/")
    }
    override fun onDestroy() { server.stop(); super.onDestroy() }
    override fun onBackPressed() { if (web.canGoBack()) web.goBack() else super.onBackPressed() }
}

private class ChatServer(private val activity: Activity) : NanoHTTPD("0.0.0.0", 8765) {
    private val db = activity.openOrCreateDatabase("my_local_chat.db", 0, null)
    private val sessions = ConcurrentHashMap<String, Long>()
    init {
        db.execSQL("CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE COLLATE NOCASE, display TEXT, salt TEXT, hash TEXT)")
        db.execSQL("CREATE TABLE IF NOT EXISTS messages(id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, text TEXT, created TEXT)")
    }
    private fun json(obj: JSONObject, status: Response.IStatus = Response.Status.OK, cookie: String? = null): Response {
        val r = newFixedLengthResponse(status, "application/json; charset=utf-8", obj.toString())
        r.addHeader("Cache-Control", "no-store"); if (cookie != null) r.addHeader("Set-Cookie", "chat_session=$cookie; Path=/; SameSite=Strict")
        return r
    }
    private fun hash(p: String, salt: ByteArray): String {
        val spec = PBEKeySpec(p.toCharArray(), salt, 240000, 256)
        return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).encoded.joinToString("") { "%02x".format(it) }
    }
    private fun random(n: Int): ByteArray = ByteArray(n).also { SecureRandom().nextBytes(it) }
    private fun user(session: IHTTPSession): Long? {
        val token = session.cookies.read("chat_session") ?: return null
        return sessions[token]
    }
    override fun serve(s: IHTTPSession): Response {
        return try {
            when (s.uri) {
                "/" -> { val html=activity.assets.open("index.html").bufferedReader().use { it.readText() }; newFixedLengthResponse(Response.Status.OK, "text/html; charset=utf-8", html) }
                "/api/me" -> { val id=user(s) ?: return json(JSONObject().put("error","auth required"), Response.Status.UNAUTHORIZED); val c=db.rawQuery("SELECT id,username,display FROM users WHERE id=?", arrayOf(id.toString())); c.moveToFirst(); val u=JSONObject().put("id",c.getLong(0)).put("username",c.getString(1)).put("display",c.getString(2)); c.close(); json(JSONObject().put("user",u)) }
                "/api/register", "/api/login" -> if (s.method != Method.POST) newFixedLengthResponse("Method not allowed") else {
                    val files=HashMap<String,String>(); s.parseBody(files); val d=JSONObject(files["postData"] ?: "{}"); val name=d.optString("username").trim(); val pass=d.optString("password"); val display=d.optString("display").trim()
                    if (!name.matches(Regex("[A-Za-zА-Яа-яЁё0-9_]{3,24}")) || pass.length !in 6..128) return json(JSONObject().put("error","Проверь логин и пароль."), Response.Status.BAD_REQUEST)
                    val id: Long
                    if (s.uri.endsWith("register")) {
                        if (display.isBlank() || display.length>32) return json(JSONObject().put("error","Укажи имя до 32 символов."), Response.Status.BAD_REQUEST)
                        val salt=random(16); val st=salt.joinToString("") { "%02x".format(it) }
                        try { db.execSQL("INSERT INTO users(username,display,salt,hash) VALUES(?,?,?,?)", arrayOf(name,display,st,hash(pass,salt))) } catch(e: Exception) { return json(JSONObject().put("error","Такой логин уже занят."), Response.Status.BAD_REQUEST) }
                        id=android.database.DatabaseUtils.longForQuery(db,"SELECT id FROM users WHERE username=?", arrayOf(name))
                    } else {
                        val c=db.rawQuery("SELECT id,salt,hash FROM users WHERE username=? COLLATE NOCASE", arrayOf(name)); if(!c.moveToFirst()) { c.close(); return json(JSONObject().put("error","Неверный логин или пароль."),Response.Status.BAD_REQUEST) }
                        id=c.getLong(0); val salt=hex(c.getString(1)); val expected=c.getString(2); c.close(); if(hash(pass,salt)!=expected) return json(JSONObject().put("error","Неверный логин или пароль."),Response.Status.BAD_REQUEST)
                    }
                    val token=random(32).joinToString("") { "%02x".format(it) }; sessions[token]=id
                    val c=db.rawQuery("SELECT id,username,display FROM users WHERE id=?", arrayOf(id.toString())); c.moveToFirst(); val u=JSONObject().put("id",c.getLong(0)).put("username",c.getString(1)).put("display",c.getString(2)); c.close()
                    json(JSONObject().put("ok",true).put("user",u),cookie=token)
                }
                "/api/logout" -> { val t=s.cookies.read("chat_session"); if(t!=null) sessions.remove(t); val r=json(JSONObject().put("ok",true)); r.addHeader("Set-Cookie","chat_session=; Path=/; Max-Age=0"); r }
                "/api/messages" -> {
                    val id=user(s) ?: return json(JSONObject().put("error","auth required"),Response.Status.UNAUTHORIZED)
                    if(s.method==Method.POST) { val files=HashMap<String,String>(); s.parseBody(files); val msg=JSONObject(files["postData"] ?: "{}").optString("text").trim(); if(msg.isEmpty() || msg.length>4000) return json(JSONObject().put("error","Пустое или слишком длинное сообщение."),Response.Status.BAD_REQUEST); val time=java.text.SimpleDateFormat("HH:mm",java.util.Locale.getDefault()).format(java.util.Date()); db.execSQL("INSERT INTO messages(user_id,text,created) VALUES(?,?,?)", arrayOf(id,msg,time)); json(JSONObject().put("ok",true)) }
                    else { val after=s.parameters["after"]?.firstOrNull()?.toLongOrNull() ?: 0L; val c=db.rawQuery("SELECT m.id,m.user_id,u.username,u.display,m.text,m.created FROM messages m JOIN users u ON u.id=m.user_id WHERE m.id>? ORDER BY m.id LIMIT 300",arrayOf(after.toString())); val arr=JSONArray(); while(c.moveToNext()) arr.put(JSONObject().put("id",c.getLong(0)).put("user_id",c.getLong(1)).put("username",c.getString(2)).put("display",c.getString(3)).put("text",c.getString(4)).put("time",c.getString(5))); c.close(); json(JSONObject().put("messages",arr)) }
                }
                else -> newFixedLengthResponse(Response.Status.NOT_FOUND,"text/plain","Not found")
            }
        } catch(e: Exception) { json(JSONObject().put("error","Ошибка приложения: ${e.message ?: "unknown"}"),Response.Status.INTERNAL_ERROR) }
    }
    private fun hex(s:String):ByteArray = s.chunked(2).map{it.toInt(16).toByte()}.toByteArray()
}
