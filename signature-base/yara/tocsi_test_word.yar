rule Tocsi_TEST_WORD {
   meta:
      description = "Detection of word file designed as a harmless test sample for Tocsi Antimalware"
      author = "Gaurav Jadhav"
      reference = "TODO_ADD_GITHUB_REFERENCE"
      score = 90
   strings:
      $header = { D0 CF 11 E0 A1 B1 1A E1 }
      $s1 = "Gaurav"
      $s2 = "Jadhav"
      $s3 = "Tocsi"
   condition:
      $header at 0 and all of ($s*)
}
