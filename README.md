# CWE for RAG

Handles CWEs for vector databae queries or retrieval-augmented generation 
(RAG) systems.

I got tired of LLMs hallucinating the use of prohibited/discouraged CWEs
in analysis activities. The CWE XML exports are also a bit inconsistent and
sometimes messy, which can frustrate root-cause analysis and triage.

This system is catered towards bridging those gaps.

The solution has two main modes:

- A complete ETL from the official CWE XML catalog

- Copying mappable or unmappable CWE markdown files for use however
  you want

- A simple one-shot query

ChromaDB and Ollama are used for the vector DB reference 
implementation.

# Quickstart

Running the ETL pipeline:

```
python etl_cwe.py run
```

Only generate and copy the mappable CWE files:

```
python etl_cwe.py run --noloading
python etl_cwe.py copy-md
```

# Schema and Markdown frontmatter

The CWE XML is transformed into an intermediary JSON schema. This schema
appears in the cached JSON collection and as the markdown frontmatter.
The schema includes only a core subset of the complete CWE listing.

The markdown body includes a search-friendly representation of the CWE's
most essential textual components. Reserving the search to a small space
reduces the need for advanced chunking strategies and generally makes it
easier to perform similarity searches.

The markdown file, with or without frontmatter, can be included in any 
vector database or LLM agent document collection. Vector databases are 
preferred for RAG, In cases where you cannot trivially use one, you may
want to upload the collection to a document folder in your provider's 
platform.

The schema is enforced in the `model.py` file and viewable in the
`cwe_schema.json` file. 

# Limitations

Due to the nature of similarity searches, and likely the limitations of
the small document bodies, this solution as-is may miss key CWEs. For 
example, the string "xss" may completely miss CWE-79 because the embedding
doesn't actually include the "xss" string in its title, description, or extended
description. Future versions of this app will take these edge cases into
consideration. 

Speaking of the small document bodies, the decision to include only these
features was mostly driven by testing against small models (20B and less).
The limitations of these context windows caused simple use cases, like
"pick the best of these six CWEs," to fail or hallucinate when the CWE document
size included too many details. The "query" reference implementation provides
implicit guidance on how to extract strategic information about any CWE based
on its metadata. It would serve RAG developers to follow an approach that
decouples the actual document from the information provided to an LLM's
context window in order to balance search fidelity with actual content 
retrieval.

Speaking of RAG solutions, despite the emphasis on RAG, the CLI reference 
implementation does not actually provide a RAG demo. This is due entirely
to discussions around the context window of different models. My opinion is
that the developer should determine the RAG context when utilizing the outputs
of a system like this one. Put another way, the point of this system is to 
normalize CWE content for use in your own RAG solution.

The reference implementation targets an Ollama embedding function with a 
local ChromaDB vector database. Real systems will almost certainly want to
utilize platforms like OpenAI, Anthropic, and cloud-hosted vector databases,
which could include Chroma Cloud. To achieve this, simply implement the 
`IEmbeddingClient` class to taste, and use it with the given loader.

Many of the overall goals of this project focus on *mappable* CWEs. The CWE
project emphasizes that practitioners leverage specific, mappable CWEs, but it
leaves an uncomfortable amount of room for interpretation. Due to LLMs' 
tendency to pull all kinds of CWEs (including, sometimes, even *prohibited*
ones), or hallucinating CWE artifacts outright, this solution is opinionated
in favor of the mappable weaknesses. With that said, practitioners should use
their best judgement when assigning root-cause weaknesses to vulnerabilities
in the wild and internally.


# Example MD file

This is the markdown file for CWE-79 (Cross-site Scripting)

```
---
abstraction: Base
background: 'The Same Origin Policy states that browsers should limit the resources
  accessible to scripts running on a given web site, or "origin", to the resources
  associated with that web site on the client-side, and not the client-side resources
  of any other sites or "origins". The goal is to prevent one site from being able
  to modify or read the contents of an unrelated site. Since the World Wide Web involves
  interactions between many sites, this policy is important for browsers to enforce.

  When referring to XSS, the Domain of a website is roughly equivalent to the resources
  associated with that website on the client-side of the connection. That is, the
  domain can be thought of as all resources the browser is storing for the user''s
  interactions with this particular site.'
capecs:
- 209
- 588
- 591
- 592
- 63
- 85
consequences:
- impact:
  - Bypass Protection Mechanism
  - Read Application Data
  note: The most common attack performed with cross-site scripting involves the disclosure
    of private information stored in user cookies, such as session information. Typically,
    a malicious user will craft a client-side script, which -- when parsed by a web
    browser -- performs some activity on behalf of the victim to an attacker-controlled
    system (such as sending all site cookies to a given E-mail address). This could
    be especially dangerous to the site if the victim has administrator privileges
    to manage that site. This script will be loaded and run by each user visiting
    the web site. Since the site requesting to run the script has access to the cookies
    in question, the malicious script does also.
  scope:
  - Access Control
  - Confidentiality
- impact:
  - Execute Unauthorized Code or Commands
  note: In some circumstances it may be possible to run arbitrary code on a victim's
    computer when cross-site scripting is combined with other flaws, for example,
    "drive-by hacking."
  scope:
  - Integrity
  - Confidentiality
  - Availability
- impact:
  - Execute Unauthorized Code or Commands
  - Bypass Protection Mechanism
  - Read Application Data
  note: The consequence of an XSS attack is the same regardless of whether it is stored
    or reflected. The difference is in how the payload arrives at the server. XSS
    can cause a variety of problems for the end user that range in severity from an
    annoyance to complete account compromise. Some cross-site scripting vulnerabilities
    can be exploited to manipulate or steal cookies, create requests that can be mistaken
    for those of a valid user, compromise confidential information, or execute malicious
    code on the end user systems for a variety of nefarious purposes. Other damaging
    attacks include the disclosure of end user files, installation of Trojan horse
    programs, redirecting the user to some other page or site, running "Active X"
    controls (under Microsoft Internet Explorer) from sites that a user perceives
    as trustworthy, and modifying presentation of content.
  scope:
  - Confidentiality
  - Integrity
  - Availability
  - Access Control
cves:
- cve_description: XSS in AI assistant
  cve_id: CVE-2024-49038
- cve_description: Plugin that enables AI features allows input with html entities,
    leading to XSS
  cve_id: CVE-2024-54142
- cve_description: Python Library Manager did not sufficiently neutralize a user-supplied
    search term, allowing reflected XSS.
  cve_id: CVE-2021-25926
- cve_description: Python-based e-commerce platform did not escape returned content
    on error pages, allowing for reflected Cross-Site Scripting attacks.
  cve_id: CVE-2021-25963
- cve_description: Universal XSS in mobile operating system, as exploited in the wild
    per CISA KEV.
  cve_id: CVE-2021-1879
- cve_description: 'Chain: improper input validation (CWE-20) in firewall product
    leads to XSS (CWE-79), as exploited in the wild per CISA KEV.'
  cve_id: CVE-2020-3580
- cve_description: Admin GUI allows XSS through cookie.
  cve_id: CVE-2014-8958
- cve_description: Web stats program allows XSS through crafted HTTP header.
  cve_id: CVE-2017-9764
- cve_description: Web log analysis product allows XSS through crafted HTTP Referer
    header.
  cve_id: CVE-2014-5198
- cve_description: 'Chain: protection mechanism failure allows XSS'
  cve_id: CVE-2008-5080
- cve_description: 'Chain: incomplete denylist (CWE-184) only checks "javascript:"
    tag, allowing XSS (CWE-79) using other tags'
  cve_id: CVE-2006-4308
- cve_description: 'Chain: incomplete denylist (CWE-184) only removes SCRIPT tags,
    enabling XSS (CWE-79)'
  cve_id: CVE-2007-5727
- cve_description: Reflected XSS using the PATH_INFO in a URL
  cve_id: CVE-2008-5770
- cve_description: Reflected XSS not properly handled when generating an error message
  cve_id: CVE-2008-4730
- cve_description: Reflected XSS sent through email message.
  cve_id: CVE-2008-5734
- cve_description: Stored XSS in a security product.
  cve_id: CVE-2008-0971
- cve_description: Stored XSS using a wiki page.
  cve_id: CVE-2008-5249
- cve_description: Stored XSS in a guestbook application.
  cve_id: CVE-2006-3568
- cve_description: 'Stored XSS in a guestbook application using a javascript: URI
    in a bbcode img tag.'
  cve_id: CVE-2006-3211
- cve_description: 'Chain: library file is not protected against a direct request
    (CWE-425), leading to reflected XSS (CWE-79).'
  cve_id: CVE-2006-3295
description: The product does not neutralize or incorrectly neutralizes user-controllable
  input before it is placed in output that is used as a web page that is served to
  other users.
extended_description: 'There are many variants of cross-site scripting, characterized
  by a variety of terms or involving different attack topologies. However, they all
  indicate the same fundamental weakness: improper neutralization of dangerous input
  between the adversary and a victim.'
id: 79
mapping: Allowed
name: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
platform_info:
  architectures: []
  is_architecture_specific: false
  is_language_specific: false
  is_os_specific: false
  is_technology_specific: true
  languages: []
  operating_systems: []
  technologies:
  - AI/ML
  - Web Based
  - Web Server

---

# CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

## Description

The product does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output that is used as a web page that is served to other users.

## Extended description

There are many variants of cross-site scripting, characterized by a variety of terms or involving different attack topologies. However, they all indicate the same fundamental weakness: improper neutralization of dangerous input between the adversary and a victim.
```