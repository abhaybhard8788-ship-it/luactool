package com.luac.tool

import android.content.Context
import android.net.Uri
import java.io.ByteArrayOutputStream
import java.io.File
import java.util.zip.*

object Engine {
    private val LUA = byteArrayOf(0x1B, 0x4C, 0x75, 0x61)
    private val JIT = byteArrayOf(0x1B, 0x4C, 0x4A)
    private val EXT = setOf("lua", "luac", "bytes", "bin", "dat", "txt", "jsc", "luab", "data")

    private fun starts(b: ByteArray, p: ByteArray) = b.size >= p.size && p.indices.all { b[it] == p[it] }
    fun isLuac(b: ByteArray) = starts(b, LUA) || starts(b, JIT)

    private fun inflate(d: ByteArray): ByteArray? = try {
        val s = if (d.size > 2 && d[0] == 0x1F.toByte() && d[1] == 0x8B.toByte())
            GZIPInputStream(d.inputStream()) else InflaterInputStream(d.inputStream())
        s.readBytes()
    } catch (e: Exception) { null }

    private fun xxtea(data: ByteArray, key: ByteArray): ByteArray? {
        val n = data.size / 4
        if (n < 2) return null
        fun rd(b: ByteArray, i: Int) = (b[i].toInt() and 255) or ((b[i + 1].toInt() and 255) shl 8) or
            ((b[i + 2].toInt() and 255) shl 16) or ((b[i + 3].toInt() and 255) shl 24)
        val v = IntArray(n) { rd(data, it * 4) }
        val kp = key.copyOf(16)
        val k = IntArray(4) { rd(kp, it * 4) }
        val delta = -0x61c88647
        var rounds = 6 + 52 / n
        var sum = rounds * delta
        var y = v[0]; var z: Int
        while (rounds-- > 0) {
            val e = (sum ushr 2) and 3
            for (p in n - 1 downTo 1) {
                z = v[p - 1]
                v[p] -= (((z ushr 5) xor (y shl 2)) + ((y ushr 3) xor (z shl 4))) xor ((sum xor y) + (k[(p and 3) xor e] xor z))
                y = v[p]
            }
            z = v[n - 1]
            v[0] -= (((z ushr 5) xor (y shl 2)) + ((y ushr 3) xor (z shl 4))) xor ((sum xor y) + (k[e] xor z))
            y = v[0]
            sum -= delta
        }
        val out = data.copyOf()
        for (i in 0 until n) for (j in 0..3) out[i * 4 + j] = (v[i] ushr (8 * j)).toByte()
        return out
    }

    /** Returns (luac bytes, method) or null if nothing worked. */
    fun decrypt(d: ByteArray, key: String, sign: String): Pair<ByteArray, String>? {
        if (d.size < 8) return null
        if (isLuac(d)) return d to "plain"
        inflate(d)?.let { if (isLuac(it)) return it to "zlib/gzip" }
        for (k in 0..255) {
            if (((d[0].toInt() xor k) and 255) == 0x1B && ((d[1].toInt() xor k) and 255) == 0x4C &&
                ((d[2].toInt() xor k) and 255) == 0x75 && ((d[3].toInt() xor k) and 255) == 0x61)
                return ByteArray(d.size) { (d[it].toInt() xor k).toByte() } to "xor-$k"
        }
        if (key.isNotEmpty()) {
            val kb = key.toByteArray()
            val x = ByteArray(d.size) { (d[it].toInt() xor kb[it % kb.size].toInt()).toByte() }
            if (isLuac(x)) return x to "xor-key"
            val sg = sign.toByteArray()
            val offs = if (sg.isNotEmpty() && starts(d, sg)) listOf(sg.size, 0) else listOf(0)
            for (o in offs) {
                val r = xxtea(d.copyOfRange(o, d.size), kb) ?: continue
                if (isLuac(r)) return r to "xxtea"
                inflate(r)?.let { if (isLuac(it)) return it to "xxtea+zlib" }
            }
        }
        return null
    }

    fun run(ctx: Context, input: Uri, output: Uri, key: String, sign: String, log: (String) -> Unit) {
        var ok = 0; var fail = 0; var skip = 0
        val tmp = File(ctx.cacheDir, "w").apply { mkdirs() }
        ZipOutputStream(ctx.contentResolver.openOutputStream(output)!!.buffered()).use { zo ->
            fun put(name: String, data: ByteArray) { zo.putNextEntry(ZipEntry(name)); zo.write(data); zo.closeEntry() }
            fun handle(name: String, data: ByteArray) {
                val r = decrypt(data, key, sign)
                if (r == null) { skip++; return }
                val (luac, how) = r
                val base = name.substringBeforeLast('.')
                try {
                    val a = File(tmp, "a.luac"); val b = File(tmp, "b.lua")
                    a.writeBytes(luac); b.delete()
                    unluac.Main.decompile(a.absolutePath, b.absolutePath)
                    put("$base.lua", b.readBytes()); ok++
                    log("OK  [$how] $name")
                } catch (e: Throwable) {
                    put("$base.decrypted.luac", luac); fail++
                    log("DEC-ONLY [$how] $name (${e.javaClass.simpleName})")
                }
            }
            val bytes = ctx.contentResolver.openInputStream(input)!!.use { it.readBytes() }
            if (bytes.size > 4 && bytes[0] == 0x50.toByte() && bytes[1] == 0x4B.toByte()) {
                ZipInputStream(bytes.inputStream()).use { zi ->
                    var e = zi.nextEntry
                    while (e != null) {
                        val ext = e.name.substringAfterLast('.', "").lowercase()
                        if (!e.isDirectory && ext in EXT) handle(e.name, zi.readBytes())
                        e = zi.nextEntry
                    }
                }
            } else handle("file.luac", bytes)
        }
        log("Done: $ok decompiled, $fail decrypted-only, $skip skipped")
    }
}
