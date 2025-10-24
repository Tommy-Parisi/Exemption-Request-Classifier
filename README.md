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

3) Add your API key to a `.env` file

Create a `.env` file in the repo root (do NOT commit it):

```
PINECONE_API_KEY=sk-<your-key-here>
```

- Add `.env` to `.gitignore`.
- Avoid sharing keys.
