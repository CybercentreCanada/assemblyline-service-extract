# Extract Service

This Assemblyline service extracts embedded files from file containers (like ZIP, RAR, 7z, ...)

**NOTE**: This service does not require you to buy any licence and is preinstalled and
working after a default installation

## Execution

The service mainly uses the 7zip library to extract files out of containers then resubmits them for
analysis.

It will also:

- Use the python tnefparse lib to parse tnef files;
- Use the xxxswf library to extract compressed swf files;
- Use unace to extract winace compressed files;
- Use mstools and custom script to attempt to decode MSOffice files;
- Extract attachments from .eml files;
- Attempt automatic decoding using a default list of passwords (see configuration section below)


## Submission Parameters & Configuration

### Parameters:

- Password: An additional password list can be provided to the service on submission (separated by two spaces)

- Continue After Extract: When true, AL will continue processing sample to other services.

### Config:

DEFAULT_PW_LIST: List of passwords used when attempting to extract from protected archives.

MAX_EMAIL_ATTACHMENT_SIZE:	Maximum size attachment to extract from a .eml file.

NAMED_EMAIL_ATTACHMENTS_ONLY: When true, service will only extract attachment files from .eml when the file name is provided.





