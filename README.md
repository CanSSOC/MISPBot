# MispBot
Search for IP addresses, domains, and URLs in MISP from Slack.

## MispBot Setup

### Before you begin
You will need the following in place to set up this slackbot:
- A Slack workspace
- A server with Python 3.10+ to host the Python MispBot application
- A MISP instance with API key (read only is ideal)

### Step 1: Create a new App in Slack

#### Creating and Naming
- Go to **"Settings & Administration"** > **"Manage Apps"** and click on the **"Build"** link in the top right corner.
- Click on the **"Create New App"** button
- Select **"From Scratch"**
- Under **"App Name"** enter **"MispBot"**
- Under **"Pick a workspace to develop your app in"** choose the workspace for the app
- Click the **"Create App"** button

#### Sockets
- Select **"Socket Mode"** in the left navigation menu and turn on **"Enable Socket Mode"**
- Enter `bot token` for the token name on the **"Generate an app-level token to enable Socket Mode"** screen and click **"Generate"**
- Click **"Done"**

#### OAuth & Permissions
Select **"OAuth & Permissions"** in the left navigation menu and add the following OAuth Scopes:
- `app_mentions:read`
- `chat:write`
- `commands`
- `im:history`
- `im:read`
- `im:write`

#### Install App
- Select **"Install App"** in the left navigation menu and click the **"Install to Workspace"** button
- Click the **"Allow"** button on the "MispBot is requesting permission to access the workspace" screen

#### Allow Users to Send Slack Commands
- Select **"App Home"** in the left navigation menu
- Scroll down to **"Messages Tab"** and check the box **"Allow users to send Slash commands and messages from the messages tab"**
- You may have to restart/refresh Slack before this takes effect

#### Add Slash Commands
- Select **"Slash Commands"** in the left navigation menu and click om the **"Create New Command"** button
- For **"Command"** enter `/mispbot`
- For **"Short Description"** enter `Make a MISP request via MispBot`
- Click **"Save"** at the bottom right

#### Enable Events
- Select **"Event Subscriptions"** in the left navigation menu
- Turn on **"Enable Events"**
- Scroll down to **"Subscribe to bot events"** section
- Add the following Bot User Events: `app_mention` and `message.im`
- Click the link to reinstall your app
- Click the **"Allow"** button on the "MispBot is requesting permission to access the workspace" screen  

#### Display Information
- Select **"Basic Information"** in the left navigation menu and scroll down to **"Display Information"**
- Set **"App name"** to `MispBot`
- Set **"Short description"** to `Search for IP addresses, domains, and URLs in MISP from Slack.`
- For **"App icon & Preview"**, Click on **"+Add App Icon"** and upload `mispbot-slack-icon.png`
- Set **"Background color"** to `#0084e3`

### Step 2: Python application
- Enable Python venv (virtual environment)
- Install the following packages:
  - `pip install pyyaml`
  - `pip install pymisp`
  - `pip install slack-bolt`
- Add MispBot tokens to `settings.yml` (see `settings.example.yml`)
  - `SLACK_APP_TOKEN`: In Slack MispBot app settings, select "Basic Information" in the left navigation menu, scroll down to "App-Level Tokens" and click on your app name for the app token.
  - `SLACK_BOT_TOKEN`: In Slack MispBot app settings, select "OAuth & Permissions" and Bot User OAuth Token
  - `LogLevel`:
    - Set to `DEBUG` for detailed information when troubleshooting issues
    - Set to `INFO` to confirm that everything is working as expected
    - Set to `WARNING` to track unexpected behaviour or potential issues (e.g., disk space low) while application is working as expected
    - Set to `ERROR` to capture when application is unable to perform some function
    - Set to `CRITICAL` to track serious errors (e.g., when an application crashes)
  - `MISP_API_KEY`: In your MISP instance, your API key can be found under /users/view/me.
  - `MISP_SERVER`: This is the URL for the MISP server with a trailing slash.
  - `MISP_VERIFY_CERT`: `FALSE` for self-signed certificates (e.g., dev environments), `TRUE` otherwise (e.g., production environments)
- Start the app handler (you should see "Bolt app is running!")

## MispBot Usage

### MispBot Commands

#### /mispbot vs @mispbot
- `/misbot` command and results are only viewable to user
- `@mispbot` command and results are visible to the entire channel

Otherwise, they work in exactly the same way:
- `/mispbot <command> <IOC>`
- `@mispbot <command> <IOC>`

#### Command: help
The help command lists all MispBot commands with instructions.

Example: `/mispbot help`

#### Command: searchip
The searchip command accepts an IP address as an argument and returns a list of published events where the IP address is listed as an attribute with the IDS flag set to True.

Example: `/mispbot searchip 93.184.216.34`

#### Command: searchipext
The searchipext command accepts an IP address as an argument and returns a list of both published and unpublished events where the IP address is listed as an attribute (regardless of whether the IDS flag is true).

Example: `/mispbot searchipext 93.184.216.34`

#### Command: searchdomain (coming soon)
The searchdomain command accepts a domain as an argument and returns a list of published events where the domain is listed as an attribute with the IDS flag set to True.

Example: `/mispbot searchdomain example.com`

#### Command: searchdomainext (coming soon)
The searchdomainext command accepts a domain as an argument and returns a list of both published and unpublished events where the domain is listed as an attribute (regardless of whether the IDS flag is true).

Example: `/mispbot searchdomainext example.com`

#### Command: reversedns (coming soon)
The reversedns command accepts an IP address as an argument and returns the domain or, in the case of multiple domains due to shared hosting, it will return the original IP address.

Example: `/mispbot reversedns 8.8.8.8`

#### Command: resolvedomain (coming soon)
The resolvedomain command accepts a domain as an argument and returns the IP address.

Example: `/mispbot resolvedomain google.com`
