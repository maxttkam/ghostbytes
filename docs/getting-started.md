## 1. Before You Begin

It is recommended to configure a virtual environment for this project, you can use the `Uv` package manager for this:

```bash
uv sync
```

## 2. Launch the application

```bash
uv run ghostbytes
```

Installing:

```bash
uv tool install
uv tool update-shell
```

## 3. Workflow Example 1: Password Encryption

A password protected encryption was implemented using key derivation funtion (ARGON2id) and AES-256 GCM mode, which provides both integrity and confidentiality.

To encrypt a file using a password, navigate to **Encrypt / Decrypt**, and select **Encrypt** and **AES (password)**. After choosing a secure password, it is recommended to **generate a random salt** (located at the bottom of the screen) to ensure that cryptographic randomness to be applied within the key derivation function.

You can append the config.conf file with the encrypted file and send it to another user.

For decryption workflow, select **Decrypt** instead of **Encrypt** and **AES (password)** for the password-based Advanced Encryption Standard (Rijndael). The button **Import Config** imports the configuration file exported from the encryptor.
Input the same password (symmetrical) and click **Decrypt**

## 4. Workflow Example 2: ML-KEM Asymmetric Encryption

For asymmetrical encryption, a key pair must be generated prior to the encryption. For modern post-quantum cryptographic algorithm, use `ML-KEM` instead of lagacy `RSA` to prevent Harvest Now Decrypt Later attacks.

To generate a ML-KEM or RSA key pair, navigate to `Generate Key Pair` and select the algorithm. You can use a password to protect the private key (or leave blank). Then select the parameter set for `ML-KEM` or set the `e` parameter for `RSA`. The `e` parameter must be a prime and should be big enough or encryption may be easily broken.

Then, navigate to `Encrypt / Decrypt`, and select the target file to be encrypted, along with the `algorithm` and public key file (select private key file for decryption). Once the required inputs have been provided, execute the operation to complete the encryption or decryption process. Ensure that private keys are stored securely and are not shared with other users, as possession of the private key allows access to the protected data.

## 6. Supporting Tools

| Tool                        | Use it when you need to...                                                                         | First-use note                                                                                                                 |
| --------------------------- | -------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------ |
| **Hash File(s) (Checksum)** | Check whether a file or folder has changed, or compare a file with a checksum from another source. | Select the file or folder, choose a hash algorithm, and optionally save the result to a checksum file.                         |
| **Random**                  | Generate random bytes for test data, salts, or other non-password output.                          | Choose a random source, set the output length, and save the generated data to a file.                                          |
| **Password Generator**      | Create a strong random passphrase for password-based encryption.                                   | Generate the passphrase before starting encryption and store it securely; it cannot be recovered if lost.                      |
| **Secure Delete**           | Permanently remove a file when ordinary deletion is not sufficient for your workflow.              | This operation is destructive. Confirm that the file is no longer needed and double-check the selected path before running it. |

## 7. Common First-Run Problems

| Problem                                     | Likely cause                                                                               | What to do                                                                                                                    |
| ------------------------------------------- | ------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------- |
| **Missing input or output path**            | A source file, folder, or destination was not selected.                                    | Choose at least one input and a writable output path before selecting **Run**.                                                |
| **Password mismatch**                       | The confirmation password does not exactly match the first password.                       | Re-enter both passwords carefully. During decryption, enter the password used for encryption.                                 |
| **Decryption fails with a password**        | The password or encryption configuration is different.                                     | Use the same password and import the configuration exported by the encryptor, including its salt and other advanced settings. |
| **Key file is missing or cannot be opened** | The selected key path is empty, incorrect, or inaccessible.                                | Select the correct key file, check that it still exists, and enter its passphrase if it is protected.                         |
| **Key pair does not work**                  | The public and private keys do not belong to the same pair, or the wrong key was selected. | Use **Verify Key Pair**, encrypt with the public key, and decrypt with the matching private key.                              |
| **Configuration import or export fails**    | The `.conf` file path is invalid, unavailable, or not readable.                            | Choose an accessible location, preserve the exported file, and import that file on the decryptor.                             |
| **Permission or file errors**               | GhostBytes cannot read the input or write to the destination.                              | Check file permissions, close applications that may lock the file, and choose a directory where you can read and write.       |
| **RSA key generation takes a long time**    | Larger RSA keys require more time to generate.                                             | Wait for the operation to finish; avoid interrupting it, especially when using a key size above 4096 bits.                    |

## 8. Next Steps

Read the [README security notes](../README.md#security-notes), [configuration reference](configuration.md), [cryptography reference](cryptography.md), and [contribution guide](../CONTRIBUTING.md).
