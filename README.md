# Prompt Injection Detection & Defense - Working Model

## Run
    pip install -r requirements.txt
    python pid_framework.py     # trains, prints metrics, runs 3 demo prompts
    python app.py               # dashboard at http://127.0.0.1:5000

## Files
- `pid_framework.py` - dataset generator, Layers 1-3, risk engine, RAG scanner, adaptive update, evaluation
- `app.py` - Flask web app (prompt analyzer, document scanner, dashboard, audit log)
- `ABSTRACT.md` - project abstract

## Pipeline (matches slide 11)
Input -> L1 sanitizer + rules -> L2 TF-IDF+LogReg -> L3 semantic model -> risk score 0-100 -> BLOCK (>=60) / REVIEW (35-59) / PASS (<35) -> dashboard + audit log + adaptive update. Documents go through the RAG scanner chunk by chunk.

## Upgrade L3 to real DistilBERT
Install `torch transformers datasets`, fine-tune `distilbert-base-uncased` on the dataset from `build_dataset()` (4 labels), and replace `self.l3` in `Detector` with a wrapper whose `predict_proba(list_of_text)` returns the softmax over the 4 classes. Nothing else needs to change.

## Important note on results
The built-in dataset is synthetic (template based), so the ~100% scores are optimistic. For your report, train on public datasets (e.g. deepset/prompt-injections, Open-Prompt-Injection from Liu et al.) and report those numbers.
