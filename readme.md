# ShareShooter

   - Searches for where to place webshells on IIS
   - .Net Assembly compatible with CobaltStrike
   - Searches shares for IIS configs/directories and writable web files
   - Parses IIS config to determine URLs and validates accessible, writable web files


## Arguments

- w
		- Show only the writable shares and then exit.
- s 
		- Specify a single share to search.
- o
		- Save stdout to a file
			
			
			- E.g. ShareShooter.exe -o %temp%\out.txt

- Default
		- Search all writable shares.


## Output Summary
- Valid URLs
- Valid WebConfigs
- Default IIS directories