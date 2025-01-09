[![Discord](https://img.shields.io/badge/chat-on%20discord-7289da.svg?sanitize=true)](https://discord.gg/GUAy9wErNu)
[![](https://img.shields.io/discord/908084610158714900)](https://discord.gg/GUAy9wErNu)
[![Static Badge](https://img.shields.io/badge/github-assemblyline-blue?logo=github)](https://github.com/CybercentreCanada/assemblyline)
[![Static Badge](https://img.shields.io/badge/github-assemblyline\_service\_extract-blue?logo=github)](https://github.com/CybercentreCanada/assemblyline-service-extract)
[![GitHub Issues or Pull Requests by label](https://img.shields.io/github/issues/CybercentreCanada/assemblyline/service-extract)](https://github.com/CybercentreCanada/assemblyline/issues?q=is:issue+is:open+label:service-extract)
[![License](https://img.shields.io/github/license/CybercentreCanada/assemblyline-service-extract)](./LICENSE)
# Extract Service

This service extracts embedded files from file containers (like ZIP, RAR, 7z, ...).

## Execution

The service uses the 7zip library to extract files out of containers then resubmits them for analysis.

It will also:

- Use the python tnefparse library to parse tnef files;
- Use the xxxswf library to extract compressed swf files;
- Use unace to extract winace compressed files;
- Use mstools and msoffcrypto to attempt to decode MSOffice files;
- Extract attachments from .eml files;
- Attempt automatic decoding using:
    - A default list of passwords (see section below)
    - An optional user-supplied password (see section below)
    - The body of an .eml file
- Use pdfdetach in poppler-utils to extract attachments from pdf samples;
- Use the NSIS Reversing Suite to recover a preview of the the original Setup.nsi;
- Debloat bloated files:
    - Windows executables: [debloat](https://github.com/Squiblydoo/debloat) and custom scripts
    - Windows installers (.msi)
    - Every other files by using a generic entropy-based calculator
- Integrates the capabilities of the now-archived [AutoItRipper service](https://github.com/CybercentreCanada/assemblyline-service-autoit-ripper);

Once this service has completed its processing, it will block samples from continuing to other services unless they are identified as the following file types:

    - Executables
    - Java files
    - Android/APK packages
    - Document files (i.e. Microsoft Office and PDF)
    - Apple/IPA packages

## Submission Parameters & Configuration

### Parameters:

- `password`: An additional password can be provided to the service on submission to decode a container.
- `extract_executable_sections`: Using the 7zip library, the service will extract sections from an executable file.
- `continue_after_extract`: When true, Assemblyline will continue processing all samples with other services no matter the file type.

### Configuration (set by administrator):

- `default_pw_list`: List of passwords used when attempting to extract from protected archives.

## Image variants and tags

Assemblyline services are built from the [Assemblyline service base image](https://hub.docker.com/r/cccs/assemblyline-v4-service-base),
which is based on Debian 11 with Python 3.11.

Assemblyline services use the following tag definitions:

| **Tag Type** | **Description**                                                                                  |      **Example Tag**       |
| :----------: | :----------------------------------------------------------------------------------------------- | :------------------------: |
|    latest    | The most recent build (can be unstable).                                                         |          `latest`          |
|  build_type  | The type of build used. `dev` is the latest unstable build. `stable` is the latest stable build. |     `stable` or `dev`      |
|    series    | Complete build details, including version and build type: `version.buildType`.                   | `4.5.stable`, `4.5.1.dev3` |

## Running this service

This is an Assemblyline service. It is designed to run as part of the Assemblyline framework.

If you would like to test this service locally, you can run the Docker image directly from the a shell:

    docker run \
        --name Extract \
        --env SERVICE_API_HOST=http://`ip addr show docker0 | grep "inet " | awk '{print $2}' | cut -f1 -d"/"`:5003 \
        --network=host \
        cccs/assemblyline-service-extract

To add this service to your Assemblyline deployment, follow this
[guide](https://cybercentrecanada.github.io/assemblyline4_docs/developer_manual/services/run_your_service/#add-the-container-to-your-deployment).

## Documentation

General Assemblyline documentation can be found at: https://cybercentrecanada.github.io/assemblyline4_docs/

# Service Extract

Ce service extrait les fichiers contenus dans d'autres archives (tel que ZIP, RAR, 7z, ...).

## Exécution

Ce service utilise 7zip pour extraire les fichiers des archives afin de les resoumettre pour les analyser.

Le service tente aussi les approches suivantes:

- Utiliser la librarie python tnefparse afin de lire les fichier tnef;
- Utiliser la librarie xxxswf pour extraire les fichiers compressés des archives swf;
- Utiliser unace pour extraire les fichiers compressés d'une archive winace;
- Utiliser mstools et msoffcrypto pour tenter de lire et décoder les fichiers Microsoft Office;
- Extraire les attachments des fichiers .eml;
- Décoder les fichiers à l'aide des éléments suivants:
    - Des mots de passes par défaut (voir ci-bas)
    - Un mot de passe soumis par l'utilisateur (voir ci-bas)
    - Le contenu d'un fichier .eml
- Utiliser la librarie pdfdetach de poppler-utils afin d'extraire les attachments d'un fichier pdf;
- Utiliser la NSIS Reversing Suite afin de reconstruire le fichier Setup.nsi original;
- Réduire les fichier artificellement gonflés:
    - Executables Windows: [debloat](https://github.com/Squiblydoo/debloat) and custom scripts
    - Fichiers d'installation Windows (.msi)
    - Tout type de fichier pouvant être détectés à l'aide d'un calculateur générique d'entropie
- Intègres les capabilités de l'ancien [service AutoItRipper](https://github.com/CybercentreCanada/assemblyline-service-autoit-ripper)

Une fois l'analyse terminée, Extract va empêcher les autres services d'analyser le fichier, à moins qu'il fasse partie d'un de ces types de fichiers:

    - Exécutables
    - Fichiers Java
    - Applications Android/APK
    - Fichier de bureautique (i.e. Microsoft Office and PDF)
    - Applications Apple/IPA

## Paramètres de Soumission et Configuration

### Paramètres:

- `password`: Un mot de passe peut être spécifié par l'utilisateur de sa soumission pour extraire les archives protégées.
- `extract_executable_sections`: En utilisant 7zip, le service extraira les différentes sections des exécutables.
- `continue_after_extract`: Lorsque `true`, Assemblyline va continuer à analyser les fichiers avec les autres services, peu importe le type de fichier.

### Configuration (configuré par l'administrateur):

- `default_pw_list`: Liste de mots de passe utilisé par défaut lors de l'extraction de fichiers d'un fichier protégé.

## Variantes et étiquettes d'image

Les services d'Assemblyline sont construits à partir de l'image de base [Assemblyline service](https://hub.docker.com/r/cccs/assemblyline-v4-service-base),
qui est basée sur Debian 11 avec Python 3.11.

Les services d'Assemblyline utilisent les définitions d'étiquettes suivantes:

| **Type d'étiquette** | **Description**                                                                                                |  **Exemple d'étiquette**   |
| :------------------: | :------------------------------------------------------------------------------------------------------------- | :------------------------: |
|   dernière version   | La version la plus récente (peut être instable).                                                               |          `latest`          |
|      build_type      | Type de construction utilisé. `dev` est la dernière version instable. `stable` est la dernière version stable. |     `stable` ou `dev`      |
|        série         | Détails de construction complets, comprenant la version et le type de build: `version.buildType`.              | `4.5.stable`, `4.5.1.dev3` |

## Exécution de ce service

Ce service est spécialement optimisé pour fonctionner dans le cadre d'un déploiement d'Assemblyline.

Si vous souhaitez tester ce service localement, vous pouvez exécuter l'image Docker directement à partir d'un terminal:

    docker run \
        --name Extract \
        --env SERVICE_API_HOST=http://`ip addr show docker0 | grep "inet " | awk '{print $2}' | cut -f1 -d"/"`:5003 \
        --network=host \
        cccs/assemblyline-service-extract

Pour ajouter ce service à votre déploiement d'Assemblyline, suivez ceci
[guide](https://cybercentrecanada.github.io/assemblyline4_docs/fr/developer_manual/services/run_your_service/#add-the-container-to-your-deployment).

## Documentation

La documentation générale sur Assemblyline peut être consultée à l'adresse suivante: https://cybercentrecanada.github.io/assemblyline4_docs/
