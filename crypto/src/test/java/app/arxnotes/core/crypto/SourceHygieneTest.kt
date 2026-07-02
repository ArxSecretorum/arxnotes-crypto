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

import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.File

/**
 * Гигиена ПУБЛИКУЕМОГО исходника крипто-ядра `:crypto`.
 *
 * Модуль выкладывается как open-source, поэтому продакшн-исходники (`src/main/java`)
 * проверяются на отсутствие следов, которые недопустимы в публичном коде:
 *  - NUL-байтов (`0x00`) — признак мусора/повреждения файла (такой байт реально
 *    однажды попадал в строковый литерал);
 *  - захардкоженных секретов (приватные ключи, присваивания паролей/токенов литералом);
 *  - личных путей (домашние каталоги локальной машины разработчика);
 *  - забытых отладочных маркеров (TODO/FIXME/«не публиковать»).
 *
 * Проверяется ТОЛЬКО `src/main` (то, что попадает в публикацию). `src/test` намеренно
 * исключён: там лежат СИНТЕТИЧЕСКИЕ тестовые учётные данные (`TestSupport.TEST_PIN`,
 * `TestSupport.TEST_PASSWORD` — публичный пример из xkcd 936), и это нормально.
 *
 * Про затирание буферов (логика M4: `pw.fill(' ')` / `out.fill(0)` в `finally`
 * в [BackupCrypto], [PinHasher], [MasterKeyManager]): напрямую из теста оно НЕ наблюдаемо —
 * буферы приватные и локальные, без хука в продакшн-код их зануление не видно снаружи.
 * Поэтому здесь оно НЕ ассертится; корректность затирания держится на ревью кода и на
 * регрессе round-trip (см. RoundTripTest/AeadIntegrityTest). Этот класс покрывает гигиену
 * самого ИСХОДНИКА, а не рантайм-поведение буферов.
 */
class SourceHygieneTest {

    /**
     * Свойство: каждый публикуемый `*.kt` читается как байты и не содержит ни одного NUL (`0x00`).
     * Зачем: NUL в текстовом исходнике — признак повреждения/мусора (некогда попадал в литерал);
     * в публичном коде такого быть не должно. Сообщение об ошибке указывает файл и смещение.
     */
    @Test
    fun productionSource_hasNoNulBytes() {
        forEachProductionKt { file ->
            val bytes = file.readBytes()
            val offset = bytes.indexOf(0.toByte())   // явный Byte: ByteArray.indexOf(Byte), не Int
            if (offset >= 0) {
                fail("NUL-байт (0x00) в публикуемом исходнике: ${file.path} @ offset $offset")
            }
        }
    }

    /**
     * Свойство: ни один публикуемый файл не содержит захардкоженных секретов.
     * Зачем: утечка приватного ключа/пароля/токена в open-source — критическая ошибка.
     * Паттерны намеренно узкие, чтобы НЕ ловить легитимный Kotlin (тип `password: String`,
     * имена методов/параметров, KDoc) — см. комментарии у каждого ниже.
     */
    @Test
    fun productionSource_hasNoHardcodedSecrets() {
        // 1) PEM-заголовок приватного ключа — однозначный признак вставленного секрета.
        val privateKeyHeader =
            Regex("-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")

        // 2) Присваивание секрета СТРОКОВЫМ ЛИТЕРАЛОМ: `secret = "..."`.
        //    Требуем именно `=` со строковым литералом справа, поэтому объявление типа
        //    `password: String` (двоеточие, без литерала) НЕ срабатывает. RegexOption.IGNORE_CASE
        //    ловит и `apiKey`, и `API_KEY`. Пустой литерал `""` исключён ([^"]+).
        val secretAssignment =
            Regex(
                "\\b(?:password|passwd|secret|apikey|api_key|token)\\s*=\\s*\"[^\"]+\"",
                RegexOption.IGNORE_CASE
            )

        // 3) Длинный base64-подобный токен ВНУТРИ строкового литерала (>= 40 символов алфавита
        //    base64). Намеренно ограничен содержимым кавычек, а не всем текстом: иначе KDoc-проза
        //    и хеш-векторы давали бы ложные срабатывания. На текущем продакшне самый длинный
        //    непрерывный литерал — доменная метка "app.safenote/db/v1" (точки рвут base64-серию),
        //    так что ложных падений нет; паттерн оставлен как защита от будущей вставки ключа.
        val base64Literal =
            Regex("\"[A-Za-z0-9+/]{40,}={0,2}\"")

        forEachProductionKt { file ->
            val text = file.readText()
            privateKeyHeader.find(text)?.let {
                fail("Похоже на приватный ключ в ${file.path}: \"${it.value.take(40)}…\"")
            }
            secretAssignment.find(text)?.let {
                fail("Похоже на захардкоженный секрет в ${file.path}: \"${it.value}\"")
            }
            base64Literal.find(text)?.let {
                fail("Подозрительный base64-литерал в ${file.path}: \"${it.value.take(48)}…\"")
            }
        }
    }

    /**
     * Свойство: в публикуемом коде нет личных путей разработчика.
     * Зачем: домашние пути локальной машины не должны утечь в публичный репозиторий.
     * Подстроки сравниваются без учёта регистра, чтобы поймать любые варианты написания.
     */
    @Test
    fun productionSource_hasNoPersonalData() {
        // Домашние пути ОС — типичный след локальной машины, случайно попавший в исходник.
        val personalMarkers = listOf(
            "C:\\Users",   // Windows-путь домашнего каталога
            "/Users/"      // macOS/Linux-путь домашнего каталога
        )
        forEachProductionKt { file ->
            val text = file.readText()
            for (marker in personalMarkers) {
                if (text.contains(marker, ignoreCase = true)) {
                    fail("Личные данные в публикуемом исходнике ${file.path}: \"$marker\"")
                }
            }
        }
    }

    /**
     * Свойство: в публикуемом коде нет забытых отладочных маркеров.
     * Зачем: TODO/FIXME/«не публиковать» в open-source — признак незавершённой работы.
     * Маркеры-аббревиатуры требуют двоеточия (`TODO:` и т.п.), чтобы НЕ ловить эти буквы
     * случайно внутри обычных слов; фразовые маркеры ищутся как подстрока без учёта регистра.
     */
    @Test
    fun productionSource_hasNoLeftoverDebugMarkers() {
        // `TODO:` / `FIXME:` / `XXX:` / `HACK:` — c двоеточием, как их обычно и пишут;
        // это исключает ложные совпадения с буквами внутри слов.
        val abbrevMarkers = Regex("\\b(?:TODO|FIXME|XXX|HACK)\\b\\s*:")
        // Фразовые «не публиковать» — без двоеточия; маловероятны внутри валидного слова.
        val phraseMarkers = listOf("do not ship", "не публиковать")

        forEachProductionKt { file ->
            val text = file.readText()
            abbrevMarkers.find(text)?.let {
                fail("Отладочный маркер в публикуемом исходнике ${file.path}: \"${it.value.trim()}\"")
            }
            for (phrase in phraseMarkers) {
                if (text.contains(phrase, ignoreCase = true)) {
                    fail("Маркер «не публиковать» в исходнике ${file.path}: \"$phrase\"")
                }
            }
        }
    }

    // --- Инфраструктура: поиск дерева продакшн-исходников и обход *.kt --------------------

    /**
     * Применяет [check] к каждому `*.kt` в продакшн-дереве `src/main/java`.
     * Заодно служит дымовой проверкой того, что дерево вообще найдено и непусто
     * (иначе остальные ассерты прошли бы «вхолостую» и пропустили бы реальную утечку).
     */
    private fun forEachProductionKt(check: (File) -> Unit) {
        val srcDir = productionSrcDir()
        val ktFiles = srcDir.walkTopDown().filter { it.isFile && it.extension == "kt" }.toList()
        assertTrue(
            "Не найдено ни одного *.kt в публикуемом дереве ${srcDir.path} — " +
                "проверка гигиены прошла бы вхолостую",
            ktFiles.isNotEmpty()
        )
        ktFiles.forEach(check)
    }

    /**
     * Находит каталог публикуемых исходников. Модульные тесты `:crypto` запускаются с рабочей
     * директорией = корень модуля (`crypto`), поэтому основной кандидат — `src/main/java`.
     * Остальные кандидаты покрывают запуск из корня проекта/другой рабочей директории.
     * Если ни один не существует — НЕ маскируем, а падаем с перечислением проверенных путей,
     * чтобы причина (неверная рабочая директория) была сразу видна.
     */
    private fun productionSrcDir(): File {
        val candidates = listOf(
            File("src/main/java"),
            File("crypto/src/main/java"),
            File("../crypto/src/main/java")
        )
        return candidates.firstOrNull { it.isDirectory }
            ?: throw AssertionError(
                "Каталог публикуемых исходников не найден. Рабочая директория: " +
                    "${File("").absolutePath}. Проверены кандидаты: " +
                    candidates.joinToString { it.path }
            )
    }
}
