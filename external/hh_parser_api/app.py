from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import subprocess
import csv
import os
from typing import List
from io import StringIO

app = FastAPI()

class ParseRequest(BaseModel):
    text: str

@app.post("/parse/")
def parse(request: ParseRequest):
    output_file = "hh_results.csv"
    command = [
        "python",
        "researcher.py",
        "--text", request.text,
        "--refresh",
        "--save_result"
    ]

    try:
        subprocess.run(command, check=True)
    except subprocess.CalledProcessError as e:
        raise HTTPException(status_code=500, detail=f"Parser error: {str(e)}")

    if not os.path.exists(output_file):
        raise HTTPException(status_code=500, detail="Parser finished, but hh_results.csv not found.")

    vacancies = []
    try:
        with open(output_file, encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                vacancies.append(row)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to parse CSV: {str(e)}")

    return {"vacancies": vacancies}
