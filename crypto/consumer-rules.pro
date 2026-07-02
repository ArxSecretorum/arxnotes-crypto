# Argon2id из BouncyCastle используется напрямую (без рефлексии/провайдера),
# но на всякий случай не предупреждаем о необязательных ветках BC и держим генераторы.
-dontwarn org.bouncycastle.**
-keep class org.bouncycastle.crypto.generators.Argon2BytesGenerator { *; }
-keep class org.bouncycastle.crypto.params.Argon2Parameters { *; }
-keep class org.bouncycastle.crypto.params.Argon2Parameters$Builder { *; }
