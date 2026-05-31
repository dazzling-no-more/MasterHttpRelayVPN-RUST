import org.gradle.api.tasks.Exec

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "com.dazzlingnomore.mhrv"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.dazzlingnomore.mhrv"
        minSdk = 24 // Android 7.0 — covers 99%+ of live devices.
        targetSdk = 35
        versionCode = 216
        versionName = "2.10.1"

        // Ship all four mainstream Android ABIs:
        //   - arm64-v8a      — 95%+ of real-world Android phones since 2019
        //   - armeabi-v7a    — older/cheaper devices still on 32-bit ARM
        //   - x86_64         — Android emulator on Intel Macs + Chromebooks
        //   - x86            — legacy 32-bit Intel emulator; cheap to include
        // Per-ABI .so files push the APK up to ~50 MB, but users expect one
        // APK that Just Works rather than "pick the right ABI" which nobody
        // does correctly. Google Play would auto-split; we ship universal.
        ndk {
            abiFilters += listOf("arm64-v8a", "armeabi-v7a", "x86_64", "x86")
        }
    }

    signingConfigs {
        create("release") {
            // Committed keystore — fixed signature across machines and
            // across CI runs. Using the auto-generated debug keystore
            // (as v1.0.0 / v1.0.1 did) makes every release APK fail to
            // install over the previous one with
            // INSTALL_FAILED_UPDATE_INCOMPATIBLE, because Android treats
            // a signature change as "different app": the user has to
            // uninstall first. That's awful UX.
            //
            // The password is in plaintext because this is an
            // open-source project without Play Store identity. A
            // forked/rebuilt APK signed with a different key is
            // fundamentally a different install path anyway — the
            // protection model here is "trust the source tree you
            // pulled from," not "trust that we hold a key you can't
            // see." If you're forking, generate your own key, commit
            // it, and ship.
            storeFile = file("release.jks")
            storePassword = "mhrv-rs-release"
            keyAlias = "mhrv-rs"
            keyPassword = "mhrv-rs-release"
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro",
            )
            signingConfig = signingConfigs.getByName("release")
        }
    }

    // Per-ABI APK splits in addition to the universal APK.
    //
    // Issue #136: GitHub Releases is filtered from inside IR, and the
    // universal APK (~50 MB, all four ABIs bundled) is the bottleneck —
    // users on slow or unstable censorship-tunnel paths often can't
    // pull down 50 MB reliably. Per-ABI APKs are ~15 MB each (only one
    // copy of librahgozar.so + libtun2proxy.so instead of four), which
    // is small enough to succeed where the universal fails.
    //
    // Keeping the universal APK too (`isUniversalApk = true`) because
    // existing download paths / docs / Telegram mirrors all reference
    // the universal name — removing it would break every link in the
    // wild. The per-ABI outputs are additive.
    splits {
        abi {
            isEnable = true
            reset()
            include("arm64-v8a", "armeabi-v7a", "x86_64", "x86")
            isUniversalApk = true
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }

    // librahgozar.so is produced by `cargo ndk` in the repo root and dropped
    // under app/src/main/jniLibs/<abi>/. The cargoBuild task below runs
    // that before each assembleDebug / assembleRelease.
    sourceSets["main"].jniLibs.srcDirs("src/main/jniLibs")

    // assets/fronting-groups/curated.json is generated into build/ by
    // the syncFrontingGroupsAssets task (defined further down). Keeping
    // generated output under build/ rather than src/ means stale copies
    // can't outlive the canonical file in the source tree, and the
    // standard build/ gitignore covers it without a carve-out under
    // src/main/assets/.
    sourceSets["main"].assets.srcDir(
        layout.buildDirectory.dir("generated/curatedAssets"),
    )

    packaging {
        resources.excludes +=
            setOf(
                "META-INF/AL2.0",
                "META-INF/LGPL2.1",
            )
    }
}

dependencies {
    val composeBom = platform("androidx.compose:compose-bom:2025.04.01")
    implementation(composeBom)
    androidTestImplementation(composeBom)

    implementation("androidx.core:core-ktx:1.15.0")
    implementation("androidx.activity:activity-compose:1.10.1")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.7")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.8.7")
    // AppCompatDelegate.setApplicationLocales is the only thing we need
    // out of AppCompat — lets us flip the whole app locale at runtime
    // from RahgozarApp.onCreate without touching every composable.
    implementation("androidx.appcompat:appcompat:1.7.0")

    // Compose UI.
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-graphics")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.material:material-icons-extended")

    // QR code generation + scanning (self-contained, no ML Kit needed).
    implementation("com.google.zxing:core:3.5.3")
    implementation("com.journeyapps:zxing-android-embedded:4.3.0")

    // rustls-platform-verifier Android companion (Kotlin helper class
    // that bridges TLS cert chain validation to Android's KeyStore).
    // The Rust crate ships the prebuilt AAR inside its `maven/`
    // subdirectory, but we copy it into the project's `libs/` to
    // avoid depending on the cargo registry's extraction layout at
    // build time. Bumped together with the Rust crate version —
    // re-copy the AAR from `~/.cargo/registry/src/.../rustls-platform-verifier-android-X.Y.Z/maven/...`
    // when bumping `rustls-platform-verifier` in the root Cargo.toml.
    // Without this AAR on the classpath, every TLS handshake logs
    // `failed to call native verifier: Error` (the JNI lookup of the
    // Kotlin helper class fails) and reqwest surfaces it as
    // `HTTP Transport`.
    implementation(files("libs/rustls-platform-verifier-0.1.1.aar"))

    debugImplementation("androidx.compose.ui:ui-tooling")
    debugImplementation("androidx.compose.ui:ui-test-manifest")

    // Local JVM unit tests (`gradlew :app:test`). JUnit 4 plus:
    //   - org.json:json — by default android.jar's stubbed JSONObject
    //     methods all return null in unit tests, which makes ConfigStore
    //     round-trip tests untestable. The org.json artifact overrides
    //     those stubs in the test classpath without affecting the device
    //     runtime. (#1033 ConfigStoreTest, CuratedGroupsTest)
    //   - Robolectric + androidx.test:core — lets ProfileStoreTest use
    //     a real Android Context without an emulator, to verify the
    //     storage invariants documented in ProfileStore.kt. (#1057)
    testImplementation("junit:junit:4.13.2")
    testImplementation("org.json:json:20240303")
    testImplementation("org.robolectric:robolectric:4.14.1")
    testImplementation("androidx.test:core:1.6.1")
}

// Pick the JUnit 4 runner for all unit-test tasks. AGP doesn't
// auto-select between JUnit 4 and 5 — without this the test task
// will compile but report `No tests found` because no runner is
// registered. (Unit tests don't pull in the cargo/JNI chain on
// their own: `testDebugUnitTest` doesn't depend on
// `mergeDebugJniLibFolders`, so the Rust crate isn't built for
// the host JVM test loop — keeps the test cycle fast.)
tasks.withType<org.gradle.api.tasks.testing.Test>().configureEach {
    useJUnit()
}

// --------------------------------------------------------------------------
// Cross-compile the Rust crate to arm64 Android and drop the .so into the
// place Android's packager looks. We hand the work off to `cargo ndk` which
// wraps the right CC / AR / linker env vars for us.
//
// This ties to the `assemble*` task so every debug/release build triggers
// a `cargo ndk` — no manual step. In CI we'd cache the target/ dir to
// avoid full rebuilds.
// --------------------------------------------------------------------------
val rustCrateDir = rootProject.projectDir.parentFile
val jniLibsDir = file("src/main/jniLibs")

// After cargo-ndk dumps artifacts into each jniLibs/<abi>/ dir, the
// tun2proxy cdylib lands as `libtun2proxy-<hash>.so` (rustc's deps/ naming
// convention, because tun2proxy is a transitive dep not a root crate).
// Android's System.loadLibrary expects a stable name, and the hash changes
// between builds, so we normalize it to `libtun2proxy.so` in every ABI dir.
// Also deletes any stale hash-suffixed copies from previous builds.
fun normalizeTun2proxySo() {
    val jniLibsRoot = file("src/main/jniLibs")
    if (!jniLibsRoot.isDirectory) return
    jniLibsRoot.listFiles()?.filter { it.isDirectory }?.forEach { abiDir ->
        val hashed =
            abiDir.listFiles { f -> f.name.matches(Regex("libtun2proxy-[0-9a-f]+\\.so")) }
                ?: emptyArray()
        val newest = hashed.maxByOrNull { it.lastModified() }
        if (newest != null) {
            val target = abiDir.resolve("libtun2proxy.so")
            if (target.exists()) target.delete()
            newest.copyTo(target, overwrite = true)
        }
        hashed.forEach { it.delete() }
    }
}

// All ABIs we ship. Keep in sync with `android.defaultConfig.ndk.abiFilters`
// above; if these drift, the APK either includes .so files with no matching
// ABI entry (dead weight) or advertises ABIs with no .so (runtime
// UnsatisfiedLinkError on devices that pick that split).
val androidAbis = listOf("arm64-v8a", "armeabi-v7a", "x86_64", "x86")

tasks.register<Exec>("cargoBuildDebug") {
    group = "build"
    // Intentionally ALWAYS uses --release. The Rust debug build is 80+MB
    // of unoptimized object code vs 3MB with release; the 20x APK bloat is
    // never worth it just for a Rust stack trace you wouldn't see in
    // logcat anyway. If you need Rust debug symbols, temporarily drop
    // `--release` below and accept the APK size.
    //
    // `--features pipeline-debug` is added ONLY here so the debug-variant
    // APK gets the real `Native.pipelineDebugJson()` snapshot that the
    // BuildConfig.DEBUG-gated overlay and HomeScreen card consume. The
    // release task below intentionally omits the feature — release users
    // don't see the overlay and shouldn't pay the atomic / HashMap cost
    // on the upload/reply hot path.
    description = "Cross-compile rahgozar for all ABIs (release + pipeline-debug)"
    workingDir = rustCrateDir
    commandLine(
        buildList<String> {
            add("cargo")
            add("ndk")
            androidAbis.forEach {
                add("-t")
                add(it)
            }
            add("-o")
            add(jniLibsDir.absolutePath)
            add("build")
            add("--release")
            add("--features")
            add("pipeline-debug")
        },
    )
    doLast { normalizeTun2proxySo() }
}

tasks.register<Exec>("cargoBuildRelease") {
    group = "build"
    description = "Cross-compile rahgozar for all ABIs (release)"
    workingDir = rustCrateDir
    commandLine(
        buildList<String> {
            add("cargo")
            add("ndk")
            androidAbis.forEach {
                add("-t")
                add(it)
            }
            add("-o")
            add(jniLibsDir.absolutePath)
            add("build")
            add("--release")
        },
    )
    doLast { normalizeTun2proxySo() }
}

// Hook the right cargo task in front of each Android build variant.
tasks.configureEach {
    when (name) {
        "mergeDebugJniLibFolders" -> dependsOn("cargoBuildDebug")
        "mergeReleaseJniLibFolders" -> dependsOn("cargoBuildRelease")
    }
}

// --------------------------------------------------------------------------
// Bundle assets/fronting-groups/curated.json into the APK so the Android
// UI's "Load curated fronting groups" button can read it without a network
// hop. The Rust crate is the single source of truth; we copy into a
// build/generated/ directory that is wired into sourceSets.main.assets
// above, so stale outputs can't survive the canonical file being deleted
// or renamed (a fresh `gradlew clean` wipes them) and we don't need a
// gitignore carve-out under src/main/assets/.
// --------------------------------------------------------------------------
val syncFrontingGroupsAssets =
    tasks.register<Copy>("syncFrontingGroupsAssets") {
        from(rustCrateDir.resolve("assets/fronting-groups"))
        include("curated.json")
        // Sub-folder so the asset opens at "fronting-groups/curated.json"
        // (matches CuratedGroups.ASSET_PATH); without the sub-dir Android
        // would expose it at the asset namespace root.
        into(layout.buildDirectory.dir("generated/curatedAssets/fronting-groups"))
    }

tasks.configureEach {
    when (name) {
        // Asset merge runs before resource processing — depending on
        // mergeDebugAssets / mergeReleaseAssets is the most precise
        // hook, but preBuild also covers the lint/compile paths that
        // need the file present (lintDebug, etc.).
        "preBuild" -> dependsOn(syncFrontingGroupsAssets)

        "mergeDebugAssets",
        "mergeReleaseAssets",
        -> dependsOn(syncFrontingGroupsAssets)
    }
}
