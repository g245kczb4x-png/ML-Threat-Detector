from huggingface_hub import create_repo, upload_folder

repo_id = "UltimateBananaman/bert-security-model"

create_repo(repo_id, exist_ok=True)

upload_folder(
    folder_path="/Users/hassanali/Desktop/ProjIdea/siem/model/securebert",
    repo_id=repo_id
)

print("Upload complete!")