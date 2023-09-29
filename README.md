# IDA Resources

Compilation of useful resources for [IDA Pro](https://hex-rays.com/ida-pro/) and [Ghidra](https://github.com/NationalSecurityAgency/ghidra)

## Games

### CS:GO

For every method you need an updated binary, to download the most updated binary use asherkin's binary files¹.
Before trying to find signatures you need to give IDA time to analyze the binary.
When IDA finish analyzing the binary it will make a generic windows sound, and will write in the bottom left idle! 

#### Method 1 - Strings (Windows + Linux)
1. Go to CS:GO leaked source-code², and find your function.
For this example i will use the function CCSPlayer::GetPercentageOfEnemyTeamKilled()³

2. Look for a string inside the function (some functions will not have strings in it, so this method is not so useful for those functions).
In the example function we can use "Invalid percentage of enemies killed\n"⁴ string that's inside the DevMsg() call.

3. After you locate the string go to IDA and open the Strings Window⁵, then Search⁶ for the string you found, then double-click on it.
Make sure you select the exact string.

4. After clicking you'll be in the data section of the binary (.rodata), in left side of the string there will be an identifier(?) (starts with small a),
  click on it once, then click x in your keyboard to see the references to this identifier. (called xrefs)

5. If there is more than 1 entry in the xrefs, try looking for more strings in the function and use them to see if you are in the right function.
        If there are no other strings, you can try to look at number of arguments in the function and compare it with the leaked code.
        You can look at function it-self and if you are familiar with assembly try to see if you recognize some of the code (like if the string is inside a if or a for / while loop).
        Note: the number of arguments and the function it-self can change from update to update so you might not have 100% identical function to the leaked code.
Luckily, in the example function, there is only 1 reference to the string, and it's our function.

6. After you found your function and you know it's the function you need the signature to, there is 2 options to get the signature,
    1. Recommended (automatic): automatic script (makesig.py)⁷, Download and use Run Script⁸ while cursor is in the function.
    2. Not Recommended (manual): Count the bytes of the function (from the start) and build the signature yourself. (To see bytes, open Options → General → Number of opcode bytes and set to 8)
     SM signatures use \x before each byte. you must check your signature is unique for the function to make sure it will target the right function.
CCSPlayer::GetPercentageOfEnemyTeamKilled()³ = \x55\x31\xC0\x89\xE5\x53\x83\xEC\x34\x8B\x5D\x08

#### Method 2 - BinDiff (Linux Only, PRO only)
1. Install BinDiff⁹

2. Download the CS:GO binary with symbols¹⁰.

3. Open it with IDA and let be analyzed, when it's done close it and remember where the analyzed binary file is (by default it's where the binary is with a .idb extension).

4. Open the most updated binary¹ (let it analyze if it's not), and open BinDiff¹¹ with the symbols analyzed binary file (.idb).

5. This can take some time to run depends on your system specs so you can do something else while it's doing it's thing.

6. After it's done, it will open some windows inside you existing IDA desktop, go to the Matched Functions window.

7. I like to import all of the functions that have high Confidence (measures how confidence BinDiff is about matching the function with the symboled function).
Note: If you don't import the results you gonna lose them after closing the IDA program.

8. You can Search⁶ for the function you want, and extract the signature like in Method 1 section 6.

#### Annex
- [1] https://users.alliedmods.net/~asherkin/public/bins/csgo/csgo/bin/
- [2] https://github.com/perilouswithadollarsign/cstrike15_src
- [3] https://github.com/perilouswithadollarsign/cstrike15_src/blob/f82112a2388b841d72cb62ca48ab1846dfcc11c8/game/server/cstrike15/cs_player.cpp#L2491-L2503
- [4] https://github.com/perilouswithadollarsign/cstrike15_src/blob/f82112a2388b841d72cb62ca48ab1846dfcc11c8/game/server/cstrike15/cs_player.cpp#L2497
- [5] Shift + F12 / View → Open subviews → Strings
- [6] Ctrl + F
- [7] https://github.com/Scags/IDA-Scripts/blob/master/makesig.py
- [8] Alt + F7 / File → Script file...
- [9] https://youtu.be/BLBjcZe-C3I?t=192
- [10] https://users.alliedmods.net/~asherkin/public/bins/csgo_symbols/csgo/bin/server.so
- [11] Shift + D / File → BinDiff...

## Useful links

- https://github.com/Scags/IDA-Scripts
- https://asherkin.github.io/vtable/
- https://kittenpopo.github.io/csgo-offsets/
- https://users.alliedmods.net/~asherkin/public/bins/csgo_symbols/
- https://forums.alliedmods.net/showthread.php?t=191171
- https://www.youtube.com/@scags3254/videos
- https://github.com/perilouswithadollarsign/cstrike15_src
- https://github.com/lua9520/source-engine-2018-hl2_src

# Ghidra
- https://github.com/nosoop/ghidra_scripts
- https://github.com/lexika979/Sigga
