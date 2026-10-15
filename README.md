# Phishing Email Analyser

A free, educational web tool that helps you spot warning signs in suspicious emails.
You paste an email, select **Analyse Email**, and get a 0–100 risk score, a classification, a list of every warning sign that contributed to the score, and suggested next steps.

> **Important:** This is a triage tool for learning. It identifies warning signs. It **cannot determine whether an email is malicious**. Never click suspicious links or open attachments just to test them.

---

## What is in this folder

| File | What it does | Plain English |
|---|---|---|
| `index.html` | The web page structure and text | The "skeleton" of the page |
| `style.css` | The look and layout | The colours, fonts and responsive design |
| `analyser.js` | The detection and scoring engine | The "brain": reads the email and applies the rules |
| `app.js` | Connects the buttons to the engine | Makes the buttons work and displays the results |
| `samples.js` | Six fictional demonstration emails | Practice emails you can load with one click |
| `README.md` | This guide | |

You do not need to install anything. Every file is plain text that a browser reads directly.

---

## How to view it on your computer

1. Open the folder `phishing-email-analyser`.
2. Double-click `index.html`. It opens in your web browser.

That is all. Everything should work offline.

> **If double-clicking shows a blank page or no results:** some browsers handle the built-in security policy differently when a file is opened directly from your computer. In that case, use one of the free hosting options below, or ask for help setting up a local preview.

## How to put it online for free (static hosting)

Because the site is just files, any free static host will do. Some options:

- **GitHub Pages**: upload the folder to a GitHub repository, then enable Pages in the repository settings.
- **Netlify Drop**: drag the folder onto the Netlify Drop page.
- **Cloudflare Pages**: connect a repository, or upload the folder directly.

Upload all six files together and keep the same folder structure. Your hosting provider will serve `index.html` as the home page.

---

## Privacy: how it protects the email

- The email is read and analysed by JavaScript running **inside your browser tab**.
- The page includes a **Content Security Policy** (a browser rule set in `index.html`) that blocks the page from making any network connection (`connect-src 'none'`). Even if something tried to send data out, the browser would refuse.
- There is **no analytics, no tracking, no cookies and no local storage**. Refreshing the page clears everything.

You can verify this yourself: open the page, press F12 (or right-click, then **Inspect**), go to the **Network** tab, and press **Analyse Email**. No new requests should appear.

---

## How the score works

Each rule in `analyser.js` is listed in the **How the score works** table on the page. In short:

1. The score starts at 0.
2. Each warning sign found adds its points. For example, "Requests your password" adds 25 points.
3. Reassuring signs (such as a passing DMARC check) subtract points.
4. The total is kept between 0 and 100.
5. The result is classified as:
   - **0–24 Low Risk**
   - **25–59 Suspicious**
   - **60–100 High Risk**

The results page shows the exact arithmetic, for example `+25 +15 +12 = 52`, so the score is never a mystery number.

### Changing the scoring
To change a rule's points, open `analyser.js`, find the rule (search for its title), and change the number in `points:`. Save the file and refresh the page. Keep in mind that changes affect every result.

### Adding a brand
In `analyser.js`, the `BRANDS` list contains each brand's "token" (the word to look for) and its official domains. Check the official domains against the brand's own website before you rely on them.

---

## Limitations (please read)

- The tool uses pattern matching. A cleverly written phishing email can avoid every rule.
- A legitimate email can trigger rules, for example a real bank email that asks you to sign in.
- It cannot open links, scan attachments, or check whether a website is real.
- Scores can reach 100 quickly. This is by design, since each rule is fixed. You can tune the points as you learn.
- Spelling and grammar are not checked.

---

## Safe practice: how to check a message

1. Do not click links or open attachments in the suspicious email.
2. Go to the organisation's official website or app by typing the address yourself.
3. Call a phone number you already know, not one listed in the email.
4. If you have already entered a password, change it straight away, turn on multi-factor authentication, and report it.

---

## About the sample emails

All six samples in `samples.js` are fictional. They use reserved domain names such as `example.com` or names ending in `.example`, which never resolve to real websites. The IP address in the first sample is from a range reserved for documentation. The shortened link in the parcel example is a non-working placeholder.
