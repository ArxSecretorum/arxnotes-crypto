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

import android.content.Context
import android.security.keystore.KeyPermanentlyInvalidatedException
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.security.KeyStore

/**
 * Тесты Keystore-зависимых частей крипто-ядра (требуют устройства/эмулятора).
 * Выполняются в изолированном тестовом приложении: свой UID, свой Keystore и filesDir,
 * реального приложения не касаются.
 */
@RunWith(AndroidJUnit4::class)
class KeyManagerInstrumentedTest {

    private val ctx: Context = ApplicationProvider.getApplicationContext()

    /** Чистый старт каждого теста: убираем блоб мастера и Keystore-алиас. */
    @Before
    fun reset() {
        File(ctx.filesDir, "master_key.bin").delete()
        File(ctx.filesDir, "master_key.bin.tmp").delete()
        runCatching {
            KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
                .takeIf { it.containsAlias("safenote_master_key") }
                ?.deleteEntry("safenote_master_key")
        }
    }

    @Test
    fun subkeys_areDeterministic_andDomainSeparated() {
        val km = MasterKeyManager(ctx)
        val db1 = km.databaseKey()
        val db2 = km.databaseKey()
        assertEquals(32, db1.size)
        assertArrayEquals("Один и тот же подключ при повторном вызове", db1, db2)
        assertFalse("db и audio — разные домены", db1.contentEquals(km.audioKey()))
    }

    @Test
    fun master_persistsAcrossInstances() {
        val first = MasterKeyManager(ctx).databaseKey()
        val second = MasterKeyManager(ctx).databaseKey()   // новый инстанс читает тот же блоб
        assertArrayEquals(first, second)
    }

    @Test
    fun audio_roundTrips_andRejectsTamperOrShortInput() {
        val crypto = AudioCrypto(MasterKeyManager(ctx))
        val plain = "голосовая заметка 🎙".toByteArray()

        val blob = crypto.encrypt(plain)
        assertArrayEquals(plain, crypto.decrypt(blob))

        blob[blob.size - 1] = (blob[blob.size - 1].toInt() xor 0x01).toByte()
        assertNull("Подмена байта → null", crypto.decrypt(blob))
        assertNull("Слишком короткий блоб → null", crypto.decrypt(ByteArray(3)))
    }

    /** Аудио шифруется/расшифровывается побайтово для пустых, юникод- и крупных данных. */
    @Test
    fun audio_roundTrips_forEmptyLargeAndUnicode() {
        val crypto = AudioCrypto(MasterKeyManager(ctx))
        val cases = listOf(
            ByteArray(0),                                        // пустые данные
            "голосовая заметка 🎙 с кириллицей".toByteArray(),     // юникод/эмодзи
            ByteArray(512 * 1024).also { java.util.Random(1).nextBytes(it) }  // крупный буфер
        )
        for (data in cases) {
            val blob = crypto.encrypt(data)
            assertArrayEquals("round-trip побайтово, size=${data.size}", data, crypto.decrypt(blob))
        }
    }

    /**
     * Логика M3: системное аннулирование Keystore-ключа (`KeyPermanentlyInvalidatedException`)
     * преобразуется в доменное [KeyInvalidatedException], а не маскируется под «битый блоб».
     * Саму аннуляцию ОС в автотесте вызвать нельзя (нужна ручная смена защиты экрана),
     * поэтому проверяем именно НАШ маппинг, бросая системное исключение вручную.
     */
    @Test
    fun mapKeystoreInvalidation_convertsSystemExceptionToDomainException() {
        try {
            mapKeystoreInvalidation { throw KeyPermanentlyInvalidatedException() }
            fail("Ожидали KeyInvalidatedException")
        } catch (e: KeyInvalidatedException) {
            // ок: системное исключение преобразовано в доменное
        }
    }

    /** Без аннулирования [mapKeystoreInvalidation] прозрачно возвращает результат блока. */
    @Test
    fun mapKeystoreInvalidation_passesThroughResultWhenNoInvalidation() {
        assertEquals(42, mapKeystoreInvalidation { 42 })
    }

    /**
     * Негативный путь корня доверия: блоб мастера повреждён, а устройство РАЗБЛОКИРОВАНО
     * (инструментальные тесты идут на разблокированном экране). Это НЕ «device locked» и
     * НЕ повод молча сгенерировать новый мастер (иначе осиротела бы существующая БД) —
     * менеджер обязан явно сообщить о повреждении. Проверяем, что databaseKey() бросает
     * ошибку про порчу, а не возвращает «новый» ключ.
     */
    @Test
    fun corruptMasterBlob_onUnlockedDevice_reportedAsCorrupt() {
        // 1) Создаём валидный мастер (блоб + Keystore-алиас).
        MasterKeyManager(ctx).databaseKey()
        // 2) Затираем блоб мусором с заведомо чужим байтом версии (0xFF != 1) → AeadBlob.open вернёт null.
        File(ctx.filesDir, "master_key.bin").writeBytes(ByteArray(64) { 0xFF.toByte() })
        // 3) Новый менеджер на разблокированном устройстве: ожидаем явный отказ «порча», не тихий новый ключ.
        try {
            MasterKeyManager(ctx).databaseKey()
            fail("Ожидали ошибку про повреждённый блоб мастера")
        } catch (e: IllegalStateException) {
            assertTrue(
                "Сообщение должно указывать на повреждение блоба: ${e.message}",
                e.message?.contains("Corrupt", ignoreCase = true) == true
            )
        }
    }
}
