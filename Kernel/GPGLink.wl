BeginPackage["ToneAr`GPGLink`"];

GPGImportKeyPair::usage = "GPGImportKeyPair[<|\"PrivateKey\" -> privateFile, \"PublicKey\" -> publicFile|>] imports a GPG key pair from the specified files.";
GPGDeleteKeyPair::usage = "GpgDeleteKeyPair[fingerprint] deletes a GPG key pair identified by its fingerprint.";
GPGListKeyPairs::usage = "GPGListKeyPairs[] returns a Dataset of all GPG keys available in the keyring.";
GPGCreateKeyPair::usage = "GPGCreateKeyPair[userId, passphrase] creates a new GPG key pair with the specified user ID and passphrase. Options include 'Email', 'Cipher', 'KeySize', 'ValidFor', and 'KeyCurve'.";

Begin["`Private`"];

$gpg = PacletObject["ToneAr/GPGLink"]["AssetLocation", "bin/gpg"];

(* -------------------------------------------------------------------------- *)
(* ::Section:: *)(* GPGImportKeyPair *)
(* Description:  Import a GPG key pair from files.
 * Return:       _?BooleanQ
 *)
GPGImportKeyPair::fail = "``";
GPGImportKeyPair::stderr = "``";
GPGImportKeyPair[keys: KeyValuePattern[{
	"PrivateKey" -> _File,
	"PublicKey"  -> _File
}]] := GPGImportKeyPair[First /@ keys];
GPGImportKeyPair[keys: KeyValuePattern[{
	"PrivateKey" -> _String?(FileExistsQ),
	"PublicKey"  -> _String?(FileExistsQ)
}]] := Module[{
		res
	},
	Enclose[
		Function[
			res = RunProcess[{$gpg, "--import", #}];
			ConfirmAssert[
				res["ExitCode"] === 0,
				"Failed to import key " <> #
			]
		] /@ keys;
		True,
		(* OnError *)
		Function[{err},
			Message[GPGImportKeyPair::fail, err["Information"]];
			Message[GPGImportKeyPair::stderr, res["StandardError"]];
			False
		]
	]
]


(* -------------------------------------------------------------------------- *)
(* ::Section:: *)(* GPGDeleteKeyPair *)
(* Description:  Delete a GPG key pair by its fingerprint.
 * Return:       _?BooleanQ
 *)
GPGDeleteKeyPair::fail = "``";
GPGDeleteKeyPair::stderr = "``";
GPGDeleteKeyPair[fprint_String] := Module[{
		res
	},
	Enclose[
		res = RunProcess[{$gpg,
			"--batch", "--yes",
			"--pinentry-mode", "loopback",
			"--delete-secret-keys", fprint
		}];
		ConfirmAssert[
			res["ExitCode"] === 0,
			"Failed to delete secret key" 
		];
		res = RunProcess[{$gpg,
			"--batch", "--yes",
			"--pinentry-mode", "loopback",
			"--delete-key", fprint
		}];
		ConfirmAssert[
			res["ExitCode"] === 0,
			"Failed to delete public key" 
		];
		True,
		(* OnError *)
		Function[{err},
			Message[GPGDeleteKeyPair::fail, err["Information"]];
			Message[GPGDeleteKeyPair::stderr, res["StandardError"]];
			False
		]
	]
]


(* -------------------------------------------------------------------------- *)
(* ::Section:: *)(* GPGListKeyPairs *)
(* Description:  List all GPG keys.
 * Return:       _Dataset
 *)
GPGListKeyPairs[] := Module[{
		res
	},
	Enclose[
		res = RunProcess[{$gpg, "--list-keys"}];
		Dataset @ StringCases[
			res["StandardOutput"],
			{
				(
					(
						((* Public Key *)
							"pub" ~~ WhitespaceCharacter .. ~~
							cipherPub : WordCharacter .. ~~ " " ~~
							datePub : (DigitCharacter | "-") .. ~~ " " ~~
							"["~~ (cabsPub: LetterCharacter..) ~~"]" ~~ WhitespaceCharacter ... ~~
							(("[expires: " ~~ expPub : (DigitCharacter | "-") .. ~~ "]") | "") ~~
							WhitespaceCharacter ... ~~
							fprintPub : WordCharacter .. ~~
							WhitespaceCharacter ...
						) ~~
						((* UserID *)
							"uid" ~~ WhitespaceCharacter .. ~~
							"[" ~~ trust : Except["\n"|"\r"] .. ~~ "]" ~~ WhitespaceCharacter ... ~~
							id : (LetterCharacter | " ") .. ~~ WhitespaceCharacter ... ~~
							(("<" ~~ email : (WordCharacter | PunctuationCharacter) .. ~~ ">")|"") ~~
							WhitespaceCharacter ...
						) ~~
						("" | ((* Sub Key *)
							"sub" ~~ WhitespaceCharacter .. ~~
							cipherSub : WordCharacter .. ~~ " " ~~
							dateSub : (DigitCharacter | "-") .. ~~ " " ~~
							"["~~ (cabsSub: LetterCharacter..) ~~"]" ~~ WhitespaceCharacter ... ~~
							(("[expires: " ~~ expSub : (DigitCharacter | "-") .. ~~ "]") | "") ~~
							WhitespaceCharacter ... ~~
							fprintSub : WordCharacter .. ~~
							WhitespaceCharacter ...
						))
						
					)
				) :> ReplaceAll[
					<|
						"UserID" -> id,
						"Email" -> email,
						"TrustLevel" -> Replace[trust, {
							("u"|" unknown") -> "Unknown",
							"ultimate" -> "Ultimate",
							"n" -> "Never",
							"m" -> "Marginal",
							"f" -> "Full",
							"r" -> "Revoked"
						}],
						"PublicKey" -> <|
							"Cipher" -> cipherPub,
							"Created" -> Replace[datePub, d : Except[""] :> DateObject[d]],
							"Expires" -> Replace[expPub, d : Except[""] :> DateObject[d]],
							"Capabilities" -> ReplaceAll[
								StringPartition[cabsPub, 1],
								{
									"E" -> "Encrypt",
									"S" -> "Sign",
									"C" -> "Certify",
									"A" -> "Authenticate",
									"R" -> "Revocation"
								}
							],
							"Fingerprint" -> fprintPub
						|>,
						"SecretKey" -> <|
							"Cipher" -> cipherSub,
							"Created" -> Replace[dateSub, d : Except[""] :> DateObject[d]],
							"Expires" -> Replace[expSub, d : Except[""] :> DateObject[d]],
							"Capabilities" -> ReplaceAll[
								StringPartition[cabsSub, 1],
								{
									"E" -> "Encrypt",
									"S" -> "Sign",
									"C" -> "Certify",
									"A" -> "Authenticate",
									"R" -> "Revocation"
								}
							],
							"Fingerprint" -> fprintSub
						|>
					|>,
					"" -> Missing[]
				]
			}
		]
	]
]


(* -------------------------------------------------------------------------- *)
(* ::Section:: *)(* GPGCreateKeyPair *)
(* Description:  Create a new GPG key pair.
 * Options:      "Email", "Cipher", "KeySize", "ValidFor", "KeyCurve"
 * Return:       _?BooleanQ
 *)
GPGCreateKeyPair // Options = {
	"Email" -> None,
	"Cipher" -> {"RSA", "RSA"},
	"KeySize" -> {2048, 2048},
	"ExpiresIn" -> "0",
	"KeyCurve" -> "default"
};
GPGCreateKeyPair[userId_String, passphrase_String, OptionsPattern[]] := Module[{
		keyParams, tmpFile, res
	},
	Enclose[
		ConfirmAssert[
			StringMatchQ[userId, WordCharacter ..],
			"User ID must be a non-empty string containing only word characters."
		];
		ConfirmAssert[
			And[
				ListQ @ OptionValue["Cipher"],
				Length[OptionValue["Cipher"]] == 2
			],
			"Cipher must be a list of two strings, e.g. {\"RSA\", \"RSA\"}."
		];
		ConfirmAssert[
			AllTrue[OptionValue["Cipher"], StringMatchQ[
				"RSA" | "ECDSA" | "EDDSA" |
				"DSA" | "ElGamal" | "default"
			]],
			"Cipher must contain valid cipher types: \"RSA\", \"ECDSA\", " <>
			"\"EDDSA\", \"DSA\", \"ElGamal\", or \"default\"."
		];
		ConfirmAssert[
			And[
				ListQ @ OptionValue["KeySize"],
				Length[OptionValue["KeySize"]] == 2,
				AllTrue[OptionValue["KeySize"], IntegerQ]
			],
			"KeySize must be a list of two integers, e.g. {2048, 2048}."
		];
		ConfirmAssert[
			OptionValue["ExpiresIn"] === "0" || QuantityQ[OptionValue["ExpiresIn"], "Time"],
			"ExpiresIn must be either \"0\" or a Quantity, e.g. Quantity[30, \"Day\"]."
		];
		keyParams = ConfirmMatch[
				StringRiffle[{
					"Key-Type: "    <> First[ OptionValue["Cipher"] ],
					"Subkey-Type: " <> Last[ OptionValue["Cipher"] ],
					"Key-Length: "  <> ToString[ First @ OptionValue["KeySize"] ],
					"Subkey-Length: " <> ToString[ Last @ OptionValue["KeySize"] ],
					"Name-Real: " <> userId,
					"Name-Email: " <> Replace[
						OptionValue["Email"],
						None -> ""
					],
					"Expire-Date: " <> StringTemplate["``d"][
						OptionValue["ExpiresIn"] //
						Quantity[#, "Day"]& /* QuantityMagnitude
					],
					"Passphrase: "<>passphrase,
					"%commit"
				},
				"\n"
			],
			_String,
			"Failed to create GPG key parameters string."
		];
		WithCleanup[
			tmpFile = ConfirmMatch[
				Export[
					FileNameJoin[{$TemporaryDirectory, "gpg-keyparams.txt"}],
					keyParams,
					"Text"
				],
				_String?(FileExistsQ),
				"Failed to create temporary file for GPG key parameters."
			]
			,
			res = RunProcess[{$gpg,
				"--batch",
				"--full-generate-key", tmpFile
			}]
			,
			DeleteFile[tmpFile];
		];
		ConfirmAssert[
			res["ExitCode"] === 0,
			"Failed to create GPG key pair." 
		];
		Success["gpg-create-success",
			<|
				"Message"   -> "GPG key pair created successfully.",
				"UserID"    -> userId,
				"Email"     -> OptionValue["Email"],
				"Cipher"    -> OptionValue["Cipher"],
				"KeySize"   -> OptionValue["KeySize"],
				"ExpiresIn" -> OptionValue["ExpiresIn"],
				"KeyCurve"  -> OptionValue["KeyCurve"]
			|>
		],
		(* OnError *)
		Function[{err},
			Message[GPGCreateKeyPair::stderr, res["StandardError"]];
			err
		]
	]
];


End[];
EndPackage[];

