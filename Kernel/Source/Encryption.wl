BeginPackage["`Encryption`", {
	"ToneAr`GPGLink`",
	"ToneAr`GPGLink`Private`"
}];


Begin["`Private`"];
(* -------------------------------------------------------------------------- *)
(* ::Section:: *)(* GPGEncryptFile *)
(* Description:  Encrypt a file for a specific recipient using GPG.
 * Return:       _String | _Failure
 *)
GPGEncryptFile::fail = "``";
GPGEncryptFile::stderr = "``";
GPGEncryptFile // Options = {
	ProcessDirectory -> Automatic
};
GPGEncryptFile[recipient_String][
	loc_String?(FileExistsQ),
	out: (Automatic | _String)  : Automatic,
	opts: OptionsPattern[]
] := GPGEncryptFile[recipient, loc, out, opts];
GPGEncryptFile[
	recipient_String,
	loc_String?(FileExistsQ),
	out: (Automatic | _String) : Automatic,
	OptionsPattern[]
] := Module[{
			res,
			output = Replace[out,
				Automatic :> (loc <> ".gpg")
			]
		},
		Enclose[
			res = RunProcess[{$gpg,
					"--batch",
					"--pinentry-mode", "loopback",
					"--recipient", recipient,
					"-o", output,
					"--encrypt", loc
				},
				ProcessDirectory -> Replace[
					OptionValue[ProcessDirectory],
					Automatic :> Directory[]
				]
			];
			ConfirmAssert[
				And[
					res["ExitCode"] === 0,
					FileExistsQ[output]
				],
				"Failed to encrypt file " <> loc
			];
			output,
			(* OnError *)
			Function[{err},
				Message[GPGEncryptFile::fail, err["Information"]];
				Message[GPGEncryptFile::stderr, res["StandardError"]];
				False
			]
		]
	];

(* -------------------------------------------------------------------------- *)
(* ::Section:: *)(* GPGDecryptFile *)
(* Description:  Decrypt a GPG-encrypted file.
 * Return: _String | _Failure
 *)
GPGDecryptFile::fail = "``";
GPGDecryptFile::stderr = "``";
GPGDecryptFile // Options = {
	ProcessDirectory -> Automatic
};
GPGDecryptFile[
	passphrase_String,
	loc_String?(FileExistsQ),
	out: (Automatic | _String) : Automatic,
	OptionsPattern[]
] := Module[{
			res,
			output = Replace[out,
				Automatic :> StringDelete[loc, ".gpg"]
			]
		},
		Enclose[
			res = RunProcess[{$gpg,
					"--batch",
					"--pinentry-mode", "loopback",
					"--passphrase", passphrase,
					"-o", output,
					"--decrypt", loc
				},
				ProcessDirectory -> Replace[
					OptionValue[ProcessDirectory],
					Automatic :> Directory[]
				]
			];
			ConfirmAssert[
				And[
					res["ExitCode"] === 0,
					FileExistsQ[output]
				],
				"Failed to decrypt file " <> loc
			];
			output,
			(* OnError *)
			Function[{err},
				Message[GPGDecryptFile::stderr, res["StandardError"]];
				err
			]
		]
	];


(* -------------------------------------------------------------------------- *)
(* ::Section:: *)(* GPGEncrypt *)
(* Description:  Encrypt a string for a specific recipient using GPG.
 * Return:       _String | _Failure
 *)
GPGEncrypt::fail = "``";
GPGEncrypt::stderr = "``";
GPGEncrypt // Options = {
	"OutputFormat" -> "String"
};
GPGEncrypt[recipient_String, in_String, OptionsPattern[]] := Module[{
		res, outType, fmtFunc, proc
	},
	Enclose[
		Switch[OptionValue["OutputFormat"],
			"Text" | "String",
				outType = "--armour";
				fmtFunc = Identity,
			"Bytes" | "ByteArray",
				outType = "--text";
				fmtFunc = StringToByteArray[#, "UTF8"]&,
			_,
				Confirm[$Failed, "Invalid OutputFormat option"]
		];
		proc = StartProcess[{$gpg,
			"--batch",
			"--pinentry-mode", "loopback",
			outType,
			"--recipient", recipient,
			"-o", "-",
			"-e"
		}];
		WriteString[proc, in];
		Close @ ProcessConnection[proc, "StandardInput"] ;
		res = ReadString[proc];
		KillProcess[proc];
		ConfirmAssert[
			StringQ[res],
			"Failed to encrypt input string"
		];
		fmtFunc @ res
		,
		(* OnError *)
		Function[{err},
			Message[GPGEncrypt::fail, err["Information"]];
			If[AssociationQ[res] && KeyExistsQ[res,"StandardError"],
				Message[GPGEncrypt::stderr, res]
			];
			$Failed
		]
	]
];


(* -------------------------------------------------------------------------- *)
(* ::Section:: *)(* GPGDecrypt *)
(* Description:  Decrypt a string using GPG with a passphrase.
 * Return:       _String | _Failure
 *)
GPGDecrypt::fail = "``";
GPGDecrypt::stderr = "``";
GPGDecrypt[in_String, passphrase_String : ""] := Module[{
		proc, res
	},
	Enclose[
		WithCleanup[
			proc = StartProcess[{$gpg,
				"--batch",
				"--pinentry-mode", "loopback",
				"--passphrase", passphrase,
				"-o", "-",
				"-d"
			}],
			WriteString[proc, in];
			Close[ProcessConnection[proc,"StandardInput"]];
			res = ReadString[proc];
			ConfirmAssert[
				StringQ[res],
				"Failed to decrypt input string"
			],
			KillProcess[proc]
		];
		StringReplace[res, {
			"\\n" -> "\n",
			"\\r" -> "\r"
		}],
		(* OnError *)
		Function[{err},
			Message[GPGDecrypt::fail, err["Information"]];
			If[AssociationQ[res] && KeyExistsQ[res,"StandardError"],
				Message[GPGDecrypt::stderr, res["standardError"]]
			];
			$Failed
		]
	]
];

End[];
EndPackage[];
