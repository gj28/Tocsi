rule Tocsi_TEST_PDF {
	meta:
		description = "Detection of word file designed as a harmless test sample for Tocsi Antivirus"
      	author = "Gaurav Jadhav"
      	reference = "ADD_GITHUB_REFERENCE"
        score = 90	

	strings:
        $magic = { 25 50 44 46 }
		$s1 = "Gaurav"
		$s2 = "Jadhav"
		$s3 = "Tocsi"

	condition:
		$magic at 0 and all of ($s*)
}