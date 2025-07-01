BeginPackage["ToneAr`GPGLink`"];

GPGImportKeyPair::usage = "GPGImportKeyPair[<|\"PrivateKey\" -> privateFile, \"PublicKey\" -> publicFile|>] imports a GPG key pair from the specified files.";
GPGDeleteKeyPair::usage = "GPGDeleteKeyPair[fingerprint] deletes a GPG key pair identified by its fingerprint.";
GPGListKeyPairs::usage = "GPGListKeyPairs[] returns a Dataset of all GPG keys available in the keyring.";
GPGCreateKeyPair::usage = "GPGCreateKeyPair[userId, passphrase] creates a new GPG key pair with the specified user ID and passphrase. Options include 'Email', 'Cipher', 'KeySize', 'ValidFor', and 'KeyCurve'.";

GPGEncrypt::usage = "GPGEncrypt[message, recipient] encrypts a message for the specified recipient using GPG.";
GPGEncryptFile::usage = "GPGEncryptFile[recipient, loc, out] encrypts a file for the specified recipient. The output file is specified by 'out' or defaults to 'loc.gpg'. Options include 'ProcessDirectory'.";
GPGDecrypt::usage = "GPGDecrypt[message, passphrase] decrypts a message using GPG with the specified passphrase.";
GPGDecryptFile::usage = "GPGDecryptFile[loc, out, passphrase] decrypts a file at 'loc' and writes the output to 'out'. If 'out' is Automatic, it defaults to 'loc' without the '.gpg' extension. Options include 'ProcessDirectory'.";

EndPackage[];