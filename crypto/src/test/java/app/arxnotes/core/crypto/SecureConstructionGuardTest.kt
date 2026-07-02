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

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * Тесты-СТРАЖИ безопасной конструкции на уровне исходника.
 *
 * Эти проверки НЕ доказывают рантайм-свойство (постоянство времени сравнения, фактическое
 * зануление байтов в RAM, качество ГСЧ) — такие свойства из публичного API не наблюдаемы.
 * Их задача — зафиксировать в коде те КОНСТРУКЦИИ, которые эти свойства обеспечивают, и
 * упасть, если будущая правка их случайно сломает (регрессия). Для публикуемой
 * крипто-библиотеки это дешёвая и надёжная страховка.
 *
 * Сканируется только публикуемый продакшн-код (`src/main`), не тесты.
 */
class SecureConstructionGuardTest {

    // Тесты запускаются с рабочей директорией = корень модуля; берём первый существующий путь.
    private val srcDir: File = listOf(
        File("src/main/java"),
        File("crypto/src/main/java"),
        File("../crypto/src/main/java")
    ).firstOrNull { it.isDirectory }
        ?: error("Не найден каталог src/main/java (cwd=${File(".").absolutePath})")

    private fun source(fileName: String): String =
        srcDir.walkTopDown().first { it.isFile && it.name == fileName }.readText()

    private fun allKotlinSources(): List<File> =
        srcDir.walkTopDown().filter { it.isFile && it.extension == "kt" }.toList()

    /**
     * #3 constant-time: сравнение PIN-хеша идёт через constant-time `MessageDigest.isEqual`,
     * а НЕ через сравнения с ранним выходом (`Arrays.equals` / `contentEquals`), которые
     * открыли бы тайминг-сторонний канал на хеш PIN.
     */
    @Test
    fun pinHasher_usesConstantTimeComparison() {
        val src = source("PinHasher.kt")
        assertTrue(
            "PinHasher должен сравнивать хеш через constant-time MessageDigest.isEqual",
            src.contains("MessageDigest.isEqual")
        )
        assertFalse(
            "PinHasher не должен использовать contentEquals (ранний выход) для сравнения хеша",
            src.contains("contentEquals")
        )
        assertFalse(
            "PinHasher не должен использовать Arrays.equals (ранний выход) для сравнения хеша",
            src.contains("Arrays.equals")
        )
    }

    /**
     * #4 затирание секретов (M4): и BackupCrypto, и PinHasher зануляют транзитные буферы
     * (копию пароля/ключевой буфер) в блоке `finally` — т.е. в т.ч. на пути исключения.
     * Проверяем, что вызов `.fill(` присутствует внутри `finally { ... }`.
     */
    @Test
    fun keyDerivation_wipesTransientBuffersInFinally() {
        // [^}]* (без флага DOTALL уже матчит переводы строк в классе символов) —
        // от "finally {" до первого ".fill(" не должно встретиться "}".
        val finallyWithFill = Regex("""finally\s*\{[^}]*?\.fill\(""")
        for (name in listOf("BackupCrypto.kt", "PinHasher.kt")) {
            assertTrue(
                "$name должен затирать буферы вызовом .fill( в блоке finally (логика M4)",
                finallyWithFill.containsMatchIn(source(name))
            )
        }
    }

    /**
     * #6 источник случайности: продакшн использует криптостойкий `SecureRandom` и НИГДЕ
     * не применяет небезопасные ГСЧ (`java.util.Random`, `Math.random`, `kotlin.random`,
     * `ThreadLocalRandom`) для ключей/солей/nonce.
     */
    @Test
    fun production_usesOnlySecureRandom() {
        val bannedRng = listOf("java.util.Random", "Math.random", "kotlin.random", "ThreadLocalRandom")
        for (file in allKotlinSources()) {
            val text = file.readText()
            for (bad in bannedRng) {
                assertFalse("${file.name} не должен использовать небезопасный ГСЧ: $bad", text.contains(bad))
            }
        }
        // Позитивно: SecureRandom действительно применяется там, где нужна случайность.
        assertTrue(
            "Продакшн должен использовать SecureRandom для ключей/солей/nonce",
            allKotlinSources().any { it.readText().contains("SecureRandom") }
        )
    }
}
