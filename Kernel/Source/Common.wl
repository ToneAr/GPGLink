BeginPackage["`Common`", {
	"ToneAr`GPGLink`",
	"ToneAr`GPGLink`Private`"
}];

Begin["`Private`"];

$gpg = If[Quiet[RunProcess[{"gpg", "-h"}, "ExitCode"] === 0],
	"gpg",
	FileNameJoin[PacletObject["ToneAr/GPGLink"]["AssetLocation", "bin/"], "gpg.exe"]
];

If[!StringQ[$gpg],
	Print["GPG executable not found"];
	Abort[]
];

End[];
EndPackage[];
