# Prompt Injection Firewall Demo Pack

This directory contains a presenter-ready corpus for the Sentinel UI. Start the
gateway, open `http://127.0.0.1:8080`, select **Upload**, and drag one of these
files into the inspection panel.

All names, addresses, credentials, URLs, invoices, and business records in this
directory are synthetic. The `.example`, `.test`, and `.invalid` domains are
intentionally non-production.

## Recommended live demo

1. Upload `11-benign-invoice.pdf` to show ordinary content passing with minimal
   disruption.
2. Upload `10-mixed-quarterly-report.pdf` to show an attack hidden among
   legitimate business facts.
3. Upload `06-hidden-html-injection.html` to demonstrate inspection of content
   that is not visible on the rendered page.
4. Upload `03-base64-encoded-attack.txt` to demonstrate bounded decoding.
5. Upload `12-context-poisoning-project-update.docx` to show a suspicious policy
   claim being quarantined.
6. Upload `14-ocr-prompt-injection.png` to finish with multimodal OCR inspection.

## Complete catalog

| File | Demonstrates | Expected action |
|---|---|---|
| `01-benign-user-message.txt` | Ordinary summarization request | Allow as untrusted |
| `02-instruction-override.txt` | Override plus secret extraction | Block |
| `03-base64-encoded-attack.txt` | Encoded instruction | Block |
| `04-security-article.md` | Quoted educational content | Allow as untrusted |
| `05-retrieval-context-poisoning.md` | Poisoned RAG content | Quarantine |
| `06-hidden-html-injection.html` | Attack inside an HTML comment | Block |
| `07-malicious-api-response.json` | Tool abuse in nested JSON | Block |
| `08-vendor-secret-extraction.eml` | Injection in external email | Block |
| `09-tool-abuse-source-code.py` | Attack inside a code comment | Block |
| `10-mixed-quarterly-report.pdf` | Attack mixed with legitimate PDF text | Block |
| `11-benign-invoice.pdf` | Normal business PDF | Allow as untrusted |
| `12-context-poisoning-project-update.docx` | Poisoned Word table | Quarantine |
| `13-benign-meeting-notes.docx` | Normal Word document | Allow as untrusted |
| `14-ocr-prompt-injection.png` | Injection visible only through OCR | Block |
| `15-benign-event-poster.png` | Normal OCR image | Allow as untrusted |

Exact findings can vary if detector thresholds are changed. OCR results also
depend on the installed Tesseract version and language data.

## Regenerate the binary documents

From the project root, after installing the project dependencies:

```powershell
python .\demo_data\generate_demo_data.py
```

The generator intentionally uses only packages already required by the gateway.

Validate every generated file against the expected firewall decision:

```powershell
python .\demo_data\validate_demo_data.py
```

OCR examples are reported as skipped when the Tesseract executable is not
installed. Any other extraction failure or policy mismatch causes a nonzero exit
code.

## Presenter notes

- Point out that the firewall preserves benign portions but replaces suspicious
  segments with quarantine markers.
- Open **Sanitized content** after inspecting a malicious document.
- Compare the benign invoice with the mixed quarterly report.
- Explain that tool, network, memory, and secret capabilities remain independent
  policy decisions even if detection misses an attack.
- Do not describe the deterministic detector as complete protection. The demo
  shows layered inspection and enforcement behavior.
