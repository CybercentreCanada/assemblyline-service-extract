# Extract Service

This Assemblyline service extracts embedded files from file containers (like ZIP, RAR, 7z ...)

**NOTE**: This service does not require you to buy any licence and is preinstalled and
working after a default installation

## Execution

The service uses the 7zip library to extract files out of containers then resubmits them for analysis.

It will also:

- Use the python tnefparse library to parse tnef files;
- Use the xxxswf library to extract compressed swf files;
- Use unace to extract winace compressed files;
- Use mstools and custom script to attempt to decode MSOffice files;
- Extract attachments from .eml files;
- Attempt automatic decoding using:
    - A default list of passwords (see section below)
    - An optional user-supplied password (see section below)
    - The body of an .eml file (separated once by whitespace characters and second on [a-zA-Z0-9]+)
- Use pdfdetach in poppler-utils to extract attachments from pdf samples;

Once this service has completed its processing, it will block samples from continuing to other services unless they are
identified as the following file types:

    - Executables
    - Java files
    - Android/APK packages
    - Document files (i.e. Microsoft Office and PDF)
    - Apple/IPA packages

**NOTE**: This service will avoid adding unnecessary files if the files are known to the system to be safe. This can be
overridden by running the service task with `deep_scan` enabled.

## Submission Parameters & Configuration

### Parameters:

- `Password`: An additional password can be provided to the service on submission to decode a container.
- `Extract PE Sections`: Using the 7zip library, the service will extract sections from an executable file.
- `Continue After Extract`: When true, AL will continue processing an eml sample to other services after any attachments
have been extracted.

### Config (set by administrator):

- `default_pw_list`: List of passwords used when attempting to extract from protected archives.
- `max_email_attachment_size`:	Maximum size attachment to extract from a .eml file.
- `named_email_attachments_only`: When true, the service will only extract attachment files from .eml when the file name is provided.
