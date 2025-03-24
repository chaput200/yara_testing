
# YARA & YARA-CI TESTS

## SUMMARY:

### YARA RULES
- What is a YARA rule?
    - YARA is a tool aimed at (but not limited to) helping malware researchers to identify and classify malware samples. With YARA you can create descriptions of malware families (or whatever you want to describe) based on textual or binary patterns.
- What is YARA-ci?
    - YARA-CI is a GitHub application that provides continuous testing for YARA rules. YARA-CI helps you to detect poorly designed rules by scanning a corpus of more than 1 million files extracted from the National Reference Software Library, a collection of well-known, traceable files maintained by the U.S. Department of Homeland Security. 
- What did I do?
    - I tested various YARA rules, specifically from the 100 days of yara github repo, and gathered usedful information. Some of this information included: a rules false negative rate, false positive rate, what it detects, and a link to a malware sample that can be used to test the rule. 
    - The data I collected can be viewed in the ```100 DAYS OF YARA 2024 FALSE POSITIVE & FALSE NEGATIVE RESULTS.xlsx``` file.
