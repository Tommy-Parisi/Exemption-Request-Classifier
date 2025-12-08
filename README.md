Exemption Request Classifier

Quick setup and usage

1) Create a virtual environment and install packages (zsh)

```bash
# create venv
python3 -m venv myvenv
source myvenv/bin/activate

# install dependencies
pip install -r requirements.txt
```

2) Create a Pinecone account and get an API key

- Go to https://app.pinecone.io/ and sign up for a free account.
- Create a project and open the Project Settings or API keys page.
- Copy your API key

3) Add your API keys to a `.env` file

Create a `.env` file in the repo root (do NOT commit it):

```
PINECONE_API_KEY=your-pinecone-api-key
GOOGLE_API_KEY=your-google-api-key
PINECONE_ENV=us-west1-gcp
PINECONE_INDEX=exemption-policy
LLM_API_KEY=your-google-api-key
LLM_API_URL=https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent
```

- Add `.env` to `.gitignore`.
- Avoid sharing keys.

## RAG Integration

The system includes a RAG (Retrieval Augmented Generation) integration that:
- Searches through security policy documents using Pinecone vector database
- Analyzes exception requests against policy requirements using Google Gemini LLM
- Generates policy compliance assessments and risk narratives

### Testing

Run the comprehensive test suite:
```bash
source myvenv/bin/activate
python tests/test_rag_integration_real.py
```

Run basic connectivity test:
```bash
python test_environment.py
```

View example usage:
```bash
python example_rag_usage.py
```

### File Structure

- `engine/rag_integration.py` - Main RAG integration class
- `tests/test_rag_integration_real.py` - Comprehensive test suite
- `test_environment.py` - Basic connectivity test
- `example_rag_usage.py` - Example usage with mock data
