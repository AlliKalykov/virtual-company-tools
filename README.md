# virtual-company-tools

## creaete virtual environment
```bash
python3 -m venv venv
```

## activate virtual environment
```bash
source venv/bin/activate
```

## install requirements
```bash
pip install -r requirements.txt
```

.env file
```bash
# slack bot api token
SLACK_TOKEN=xx
SLACK_CHANNEL_ID=xxx

# jira api token
JIRA_TOKEN=xxx
JIRA_API_URL=https://PROJECT NAME.atlassian.net/
JIRA_EMAIL=xxx
JIRA_BOARD_ID=1
````

take slack bot api token guide
https://docs.google.com/document/d/1LbTfhdBCDuqezXYCCZK8rTt0vI2iHZLBsea5m-nPdKE/edit?usp=sharing

- to run the slack bot
```bash
python slack_bot.py
```


take jira api token guide
https://docs.google.com/document/d/1CFDWxoqEn6JClmwhysOuJJoG4rbK3Ai8ByQia0FCAkY/edit?usp=sharing

- to run the jira bot
```bash
python jira_bot.py
```