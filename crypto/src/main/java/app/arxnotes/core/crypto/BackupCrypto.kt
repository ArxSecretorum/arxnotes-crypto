/*
 * Copyright 2026 Arx Secretorum
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package app.arxnotes.core.crypto

import org.bouncycastle.crypto.generators.Argon2BytesGenerator
import org.bouncycastle.crypto.params.Argon2Parameters
import java.nio.ByteBuffer
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Парольное шифрование файлов бэкапа: Argon2id (KDF) + AES-256-GCM.
 *
 * Формат файла:
 *   [4]  magic "SNBK"
 *   [1]  version = 2
 *   [1]  kdf id  = 1 (Argon2id)
 *   [4]  Argon2 memory, KiB (big-endian int)
 *   [1]  Argon2 iterations (passes)
 *   [1]  Argon2 parallelism
 *   [32] соль
 *   [12] AES-GCM nonce
 *   [N]  шифртекст + 16-байт GCM-тег
 *
 * Параметры KDF лежат в заголовке — их можно усиливать, не ломая старые файлы
 * (читаются по сохранённым значениям). Неверный пароль/повреждение → decrypt() == null.
 */
object BackupCrypto {

    private val MAGIC = "SNBK".toByteArray(Charsets.US_ASCII)
    private const val VERSION: Byte = 2
    private const val KDF_ARGON2ID: Byte = 1

    private const val SALT_SIZE = 32
    private const val IV_SIZE = 12
    private const val KEY_BYTES = 32
    private const val GCM_TAG_BITS = 128

    // Параметры Argon2id по умолчанию для новых бэкапов (бэкап редкий → можно «дорого»).
    private const val ARGON2_MEMORY_KIB = 65_536  // 64 MiB
    private const val ARGON2_ITERATIONS = 3
    private const val ARGON2_PARALLELISM = 1

    // Верхние границы для параметров ИЗ ЗАГОЛОВКА (он не аутентифицирован до проверки тега):
    // не даём злонамеренному файлу заказать неподъёмный Argon2 → защита от DoS/OOM.
    // Потолки с запасом над нашими дефолтами (64 MiB / t=3 / p=1), но достаточно низкие,
    // чтобы чужой файл не подвесил/не уронил устройство (в т.ч. бюджетное на minSdk 26)
    // ещё до проверки GCM-тега. Наши бэкапы всегда p=1, поэтому снижение p-потолка их не ломает.
    private const val MAX_MEMORY_KIB = 1 shl 17   // 128 MiB
    private const val MAX_ITERATIONS = 10
    private const val MAX_PARALLELISM = 4

    private const val HEADER_SIZE = 4 + 1 + 1 + 4 + 1 + 1 + SALT_SIZE + IV_SIZE

    fun encrypt(plaintext: ByteArray, password: String): ByteArray {
        val rng = SecureRandom()
        val salt = ByteArray(SALT_SIZE).also { rng.nextBytes(it) }
        val iv = ByteArray(IV_SIZE).also { rng.nextBytes(it) }
        val key = deriveKey(password, salt, ARGON2_MEMORY_KIB, ARGON2_ITERATIONS, ARGON2_PARALLELISM)

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(GCM_TAG_BITS, iv))
        val ciphertext = cipher.doFinal(plaintext)

        return ByteBuffer.allocate(HEADER_SIZE + ciphertext.size).apply {
            put(MAGIC)
            put(VERSION)
            put(KDF_ARGON2ID)
            putInt(ARGON2_MEMORY_KIB)
            put(ARGON2_ITERATIONS.toByte())
            put(ARGON2_PARALLELISM.toByte())
            put(salt)
            put(iv)
            put(ciphertext)
        }.array()
    }

    fun decrypt(data: ByteArray, password: String): ByteArray? {
        if (data.size < HEADER_SIZE + GCM_TAG_BITS / 8) return null
        val buf = ByteBuffer.wrap(data)

        val magic = ByteArray(MAGIC.size).also { buf.get(it) }
        if (!magic.contentEquals(MAGIC)) return null
        if (buf.get() != VERSION) return null
        if (buf.get() != KDF_ARGON2ID) return null

        val memoryKib = buf.int
        val iterations = buf.get().toInt() and 0xFF
        val parallelism = buf.get().toInt() and 0xFF
        // Отбрасываем заведомо абсурдные/злонамеренные параметры ДО запуска Argon2.
        if (memoryKib !in 1..MAX_MEMORY_KIB ||
            iterations !in 1..MAX_ITERATIONS ||
            parallelism !in 1..MAX_PARALLELISM
        ) return null

        val salt = ByteArray(SALT_SIZE).also { buf.get(it) }
        val iv = ByteArray(IV_SIZE).also { buf.get(it) }
        val ciphertext = ByteArray(buf.remaining()).also { buf.get(it) }

        return runCatching {
            val key = deriveKey(password, salt, memoryKib, iterations, parallelism)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(GCM_TAG_BITS, iv))
            cipher.doFinal(ciphertext)
        }.getOrNull()   // null при неверном пароле (несовпадение GCM-тега) или повреждении
    }

    private fun deriveKey(
        password: String,
        salt: ByteArray,
        memoryKib: Int,
        iterations: Int,
        parallelism: Int
    ): SecretKeySpec {
        val params = Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
            .withVersion(Argon2Parameters.ARGON2_VERSION_13)
            .withSalt(salt)
            .withMemoryAsKB(memoryKib)
            .withIterations(iterations)
            .withParallelism(parallelism)
            .build()
        val generator = Argon2BytesGenerator().apply { init(params) }
        val out = ByteArray(KEY_BYTES)
        val pw = password.toCharArray()
        try {
            generator.generateBytes(pw, out)
            return SecretKeySpec(out, "AES")  // SecretKeySpec копирует байты внутрь
        } finally {
            pw.fill(' ')   // затираем копию пароля (в т.ч. на пути исключения)
            out.fill(0)    // затираем транзитный ключевой буфер (ключ уже скопирован)
        }
    }
}
