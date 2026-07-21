// Phishing Awareness Training Platform - Application State & Logic
// SECURITY FIX [F8]: Entire application wrapped in IIFE to prevent global scope leakage

;(() => {
    'use strict';

    // SECURITY FIX [F1]: HTML sanitization utility to prevent XSS via innerHTML
    function escapeHTML(str) {
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }

    // SECURITY FIX [F7]: Name validation regex (letters, spaces, hyphens, periods, apostrophes)
    const NAME_REGEX = /^[A-Za-z\s\-\.']{2,100}$/;

    const state = Object.seal({
        progress: 0,
        unlockedModules: {
            dashboard: true,
            basics: true,
            email: false,
            websites: false,
            quiz: false,
            certificate: false
        },
        completedModules: {
            basics: false,
            email: false,
            websites: false,
            quiz: false
        },
        activeTab: 'dashboard',
        
        // Module 2 (Email Inspector) States
        emailHotspotsFound: new Set(),
        emailVerdict: null,
        
        // Module 3 (Website Spotter) States
        currentSelectedSite: 'A',
        siteVerdict: null,
        
        // Module 4 (Quiz) States
        quizStarted: false,
        currentQuestionIndex: 0,
        quizScore: 0,
        quizAnswers: [],
        userName: ""
    });

    // Quiz Question Database — kept private inside IIFE (SECURITY FIX [F8])
    const quizQuestions = Object.freeze([
        {
            id: 1,
            category: "vishing",
            icon: "📞",
            title: "The Tech Support Call",
            context: "You receive an urgent phone call from 'Microsoft IT Department'. The caller claims your workstation is broadcasting suspicious malware traffic. They ask you to quickly download a remote access tool (e.g. AnyDesk) and read them a 2FA authorization code to 'clean the infection'. What do you do?",
            options: Object.freeze([
                {
                    text: "Download the tool immediately and assist them; they are security professionals.",
                    correct: false,
                    explanation: "Incorrect. Legitimate technology companies never cold-call users demanding immediate remote access downloads or access codes."
                },
                {
                    text: "Refuse, hang up, and report the caller to your corporate IT Helpdesk through official internal channels.",
                    correct: true,
                    explanation: "Correct! This is a typical Vishing (voice phishing) attack. Always hang up and verify their identity by calling your official IT helpdesk directly."
                },
                {
                    text: "Give them the remote access credentials but withhold your personal passwords.",
                    correct: false,
                    explanation: "Incorrect. Giving remote access allows the hacker to install malicious software, steal sessions, and copy locally stored files."
                }
            ])
        },
        {
            id: 2,
            category: "smishing",
            icon: "💬",
            title: "The Package Delivery Alert",
            context: "You receive a text message: 'USPS Notice: Your package cannot be delivered due to an incorrect house number. Please update your details and settle the fee ($1.50) at: http://usps-redelivery-portal.info/update'. What should you check first?",
            options: Object.freeze([
                {
                    text: "Click the link. It's only $1.50, and you want your package.",
                    correct: false,
                    explanation: "Incorrect. Clicking links in unsolicited SMS messages frequently exposes you to malware downloads or credential harvesting."
                },
                {
                    text: "Inspect the URL domain. Since it ends in '.info' and isn't 'usps.com', it's highly suspicious.",
                    correct: true,
                    explanation: "Correct! Legitimate government and postal offices use secure domains (like .com or .gov). Typo domains ending in .info or .biz are common red flags."
                },
                {
                    text: "Reply back to the sender asking them to verify their employee identity.",
                    correct: false,
                    explanation: "Incorrect. Replying to phishing text numbers signals that your phone number is active, leading to even more spam and phishing messages."
                }
            ])
        },
        {
            id: 3,
            category: "social-engineering",
            icon: "💾",
            title: "The Abandoned USB Drive",
            context: "While walking into the office lobby, you find a brand new USB drive labeled 'Confidential Q3 Payroll & Bonuses' lying on the floor next to the elevators. What is the safest course of action?",
            options: Object.freeze([
                {
                    text: "Take it to your desk and plug it in to see which employee lost it so you can return it.",
                    correct: false,
                    explanation: "Incorrect! plugging in unknown USB drives is a primary cyber attack vector ('USB Drop'). It can automatically launch malware (like keystroke loggers or ransomware) on your machine."
                },
                {
                    text: "Use a home computer that is not connected to the work network to inspect the contents safely.",
                    correct: false,
                    explanation: "Incorrect. You put your personal computer at risk. Safe analysis requires a sandbox/isolated lab environment."
                },
                {
                    text: "Do not plug it in. Hand the USB drive directly to your corporate security team or IT helpdesk immediately.",
                    correct: true,
                    explanation: "Correct! Leaving malicious flash drives is a common tactic. Handing it to IT security ensures they can analyze it safely."
                }
            ])
        },
        {
            id: 4,
            category: "credential-harvesting",
            icon: "✉️",
            title: "The Shared Document Link",
            context: "You receive an email from your division's HR director sharing a Google Drive document: 'Q4 Performance Review Checklist'. Clicking the link takes you to a Google Sign-In page, but the browser address bar reads: 'https://google-drive.document-portal.com/login'. What do you do?",
            options: Object.freeze([
                {
                    text: "Enter your corporate credentials; it's a normal Google sign-in look.",
                    correct: false,
                    explanation: "Incorrect. The login screen is a fake lookalike. The domain is 'document-portal.com', NOT Google. Entering details sends your password to hackers."
                },
                {
                    text: "Close the page, check with HR via internal chat (Teams/Slack) to confirm if they sent it, and report the email.",
                    correct: true,
                    explanation: "Correct! This is credential harvesting. The address bar proves it's not Google. Always verify suspicious document links with colleagues."
                },
                {
                    text: "Try signing in with a fake password first to see if it rejects it.",
                    correct: false,
                    explanation: "Incorrect. Even if you use a fake password, it collects whatever you type, and some phishing tools accept anything and redirect you to trick you further."
                }
            ])
        },
        {
            id: 5,
            category: "authority-lure",
            icon: "👔",
            title: "The CEO's Urgent Request",
            context: "An email arrives from 'ceo-executive@yourcompany-mail-group.com'. It reads: 'Hey, I'm stuck in an offsite meeting. I need to send gift cards to clients immediately. Buy $500 in Apple gift cards, scratch the backs, and email me photos of the codes. Do this quickly and don't tell anyone, it's a surprise.' What is the giveaway here?",
            options: Object.freeze([
                {
                    text: "The CEO is demanding secrecy, bypasses normal finance protocols, and is using an external email domain.",
                    correct: true,
                    explanation: "Correct! Urgency, secrecy, bypassing official purchasing processes, and using a slightly altered domain (e.g. 'company-mail-group.com') are hallmarks of Business Email Compromise (BEC)."
                },
                {
                    text: "Nothing is wrong. CEOs frequently ask employees to execute quick purchases using their personal money.",
                    correct: false,
                    explanation: "Incorrect. Company executives do not request subordinates to buy gift cards with personal funds and send photos of codes under secrecy."
                },
                {
                    text: "The request is safe because the CEO's profile picture is shown in the email client header.",
                    correct: false,
                    explanation: "Incorrect. Profile pictures and display names can be easily spoofed or downloaded from LinkedIn."
                }
            ])
        }
    ]);

    // Red flags details for Email Inspector
    const emailRedFlags = Object.freeze({
        "sender-flag": {
            title: "Spoofed Sender Domain",
            text: "The sender's name says 'PayPal Security', but look closely at the email address: <code>support@paypa1-security-verification.com</code>. The name uses the number '1' instead of the letter 'l' (paypa1). Attackers buy lookalike domains (typosquatting) to bypass suspicion."
        },
        "subject-flag": {
            title: "High Urgency & Threat",
            text: "The subject line contains <code>URGENT</code>, <code>Verification Required Immediately!</code>, and a warning emoji. Attackers use urgency and threat (threat of losing account access) to provoke fear so you act before thinking."
        },
        "greeting-flag": {
            title: "Generic Opening Salutation",
            text: "The email opens with <code>Dear Valued Customer</code>. Genuine organizations with whom you have accounts (like PayPal, Google, or your bank) will address you by your actual registered name. Generic greetings indicate a mass-phishing campaign."
        },
        "link-flag": {
            title: "Deceptive Link Target",
            text: "The button states 'Confirm Identity', but the destination is <code>http://verification-paypal-update.net/identity/login.php</code>. It uses the unsafe <code>http</code> protocol (no encryption) and links to a non-PayPal domain. Always inspect links by hovering over them."
        },
        "attachment-flag": {
            title: "Double Extension Attachment",
            text: "The attached invoice is named <code>Account_Settlement_Detail.pdf.exe</code>. Windows hides common extensions, so a user might only see '.pdf', but the real extension is <code>.exe</code>. Opening it runs an executable program that installs malware."
        }
    });

    // DOM Elements cache
    let navItems, tabPanels, btnStartHero;

    // Wait for DOM load
    document.addEventListener("DOMContentLoaded", () => {
        initElements();
        setupNavigation();
        setupInteractiveBasics();
        setupEmailInspector();
        setupWebsiteSpotter();
        setupQuiz();
        updateUIStates();
    });

    function initElements() {
        navItems = document.querySelectorAll(".nav-item");
        tabPanels = document.querySelectorAll(".tab-panel");
        btnStartHero = document.getElementById("start-training-hero");
        
        if (btnStartHero) {
            btnStartHero.addEventListener("click", () => {
                switchTab("module-basics");
            });
        }
    }

    // ==========================================================================
    // TABS & NAVIGATION STATE SYSTEM
    // ==========================================================================
    function setupNavigation() {
        navItems.forEach(item => {
            item.addEventListener("click", () => {
                const targetTab = item.getAttribute("data-tab");
                if (state.unlockedModules[targetTab]) {
                    switchTab(targetTab);
                } else {
                    showLockWarning(targetTab);
                }
            });
        });

        // Handle Module Cards click navigation on Dashboard
        document.querySelectorAll(".module-card").forEach(card => {
            card.addEventListener("click", () => {
                const targetTab = card.getAttribute("data-target");
                if (state.unlockedModules[targetTab]) {
                    switchTab(targetTab);
                } else {
                    showLockWarning(targetTab);
                }
            });
        });

        // Proceed buttons inside modules
        const btnNextEmail = document.getElementById("btn-next-to-email");
        if (btnNextEmail) {
            btnNextEmail.addEventListener("click", () => {
                state.completedModules.basics = true;
                state.unlockedModules.email = true;
                calculateProgress();
                switchTab("module-email");
            });
        }
    }

    function switchTab(tabId) {
        state.activeTab = tabId;
        
        // Toggle active tab buttons in navbar
        navItems.forEach(item => {
            if (item.getAttribute("data-tab") === tabId) {
                item.classList.add("active");
            } else {
                item.classList.remove("active");
            }
        });

        // Toggle active panel visibility
        tabPanels.forEach(panel => {
            if (panel.id === tabId) {
                panel.classList.add("active");
            } else {
                panel.classList.remove("active");
            }
        });

        // Update Top Header Title
        const titleMap = {
            'dashboard': 'Training Dashboard',
            'module-basics': '1. Phishing & Tactics',
            'module-email': '2. Email Inspector Simulator',
            'module-websites': '3. Website Validator Simulator',
            'module-quiz': '4. Interactive Cyber Quiz'
        };
        
        const pageTitle = document.getElementById("page-title");
        if (pageTitle && titleMap[tabId]) {
            pageTitle.textContent = titleMap[tabId];
        }

        // Scroll to top of panel
        window.scrollTo({ top: 0, behavior: 'smooth' });
        updateUIStates();
    }

    function showLockWarning(tabId) {
        const errorMessages = {
            'module-email': "Please complete Module 1: Phishing Basics first to unlock this simulator.",
            'module-websites': "Please complete Module 2: Email Inspector first to unlock this simulator.",
            'module-quiz': "Please complete Module 3: Website Spotter first to unlock the Assessment Quiz.",
            'module-certificate': "You must pass the Scenario Quiz with 80%+ to unlock your Certificate of Completion."
        };
        alert(errorMessages[tabId] || "This section is currently locked. Complete previous training modules.");
    }

    function calculateProgress() {
        let completedCount = 0;
        if (state.completedModules.basics) completedCount++;
        if (state.completedModules.email) completedCount++;
        if (state.completedModules.websites) completedCount++;
        if (state.completedModules.quiz) completedCount++;
        
        state.progress = completedCount * 25;
        
        // Update progress bar
        const progressFill = document.getElementById("progress-fill");
        const progressText = document.getElementById("progress-text");
        if (progressFill) progressFill.style.width = `${state.progress}%`;
        if (progressText) progressText.textContent = `${state.progress}%`;
    }

    function updateUIStates() {
        calculateProgress();
        
        // Update modules locking display on Dashboard
        updateCardStatus("basics", "basics", "Started");
        updateCardStatus("email", "basics", "Locked");
        updateCardStatus("websites", "email", "Locked");
        updateCardStatus("quiz", "websites", "Locked");
    }

    function updateCardStatus(cardId, dependencyId, defaultLabel) {
        const statusLabel = document.getElementById(`status-${cardId}`);
        if (!statusLabel) return;
        
        if (state.completedModules[cardId]) {
            statusLabel.textContent = "Completed";
            statusLabel.className = "module-status completed";
            state.unlockedModules[cardId] = true;
        } else if (state.completedModules[dependencyId] || cardId === 'basics') {
            statusLabel.textContent = "Available";
            statusLabel.className = "module-status started";
            state.unlockedModules[cardId] = true;
        } else {
            statusLabel.textContent = "Locked";
            statusLabel.className = "module-status locked";
            state.unlockedModules[cardId] = false;
        }
    }

    // ==========================================================================
    // MODULE 1: BASICS & ACCORDIONS/FLIPS
    // ==========================================================================
    function setupInteractiveBasics() {
        // Accordion Control
        const accordionTitles = document.querySelectorAll(".accordion-title");
        accordionTitles.forEach(title => {
            title.addEventListener("click", () => {
                const item = title.parentElement;
                const isActive = item.classList.contains("active");
                
                // Close all
                document.querySelectorAll(".accordion-item").forEach(accItem => {
                    accItem.classList.remove("active");
                });
                
                // Toggle clicked
                if (!isActive) {
                    item.classList.add("active");
                }
            });
        });

        // Flip Card Control
        const flipCards = document.querySelectorAll(".flip-card");
        flipCards.forEach(card => {
            card.addEventListener("click", () => {
                card.classList.toggle("flipped");
            });
        });
    }

    // ==========================================================================
    // MODULE 2: EMAIL INSPECTOR SIMULATOR
    // ==========================================================================
    function setupEmailInspector() {
        const hotspots = document.querySelectorAll(".email-simulator .hotspot");
        const cluesFoundText = document.getElementById("clues-found");
        const verdictBox = document.getElementById("verdict-controls-box");
        const btnSafe = document.getElementById("verdict-safe");
        const btnPhish = document.getElementById("verdict-phish");

        // SECURITY FIX [F4]: Prevent default on the simulated phishing link via addEventListener
        const emailLink = document.getElementById('hs-link');
        if (emailLink) {
            emailLink.addEventListener('click', (e) => e.preventDefault());
        }

        hotspots.forEach(spot => {
            spot.addEventListener("click", () => {
                const flagId = spot.getAttribute("data-ref");
                if (!flagId || state.emailHotspotsFound.has(flagId)) return;
                
                // Add to findings
                state.emailHotspotsFound.add(flagId);
                spot.classList.add("checked");
                
                // Update counter
                if (cluesFoundText) cluesFoundText.textContent = state.emailHotspotsFound.size;
                
                // Unlock finding card details
                const findingCard = document.getElementById(flagId);
                if (findingCard) {
                    findingCard.classList.remove("locked");
                    findingCard.classList.add("unlocked");
                    
                    const statusMarker = findingCard.querySelector(".status-marker");
                    if (statusMarker) statusMarker.textContent = "Uncovered";
                    
                    // SECURITY FIX [F2]: Red flag text comes from a frozen internal object
                    // which is safe, but we still use innerHTML carefully since the data
                    // contains intentional <code> markup for educational display.
                    // In production, use a template system instead.
                    const details = findingCard.querySelector(".finding-details");
                    if (details && emailRedFlags[flagId]) {
                        details.innerHTML = emailRedFlags[flagId].text;
                    }
                }
                
                // Check if all found
                if (state.emailHotspotsFound.size === 5) {
                    if (verdictBox) verdictBox.classList.remove("disabled");
                    if (btnSafe) btnSafe.disabled = false;
                    if (btnPhish) btnPhish.disabled = false;
                    
                    const warningText = verdictBox.querySelector(".warning-text");
                    if (warningText) warningText.textContent = "Inspector scan complete. Enter verdict below.";
                }
            });
        });

        if (btnSafe) {
            btnSafe.addEventListener("click", () => {
                state.emailVerdict = "safe";
                showEmailVerdictFeedback(false);
            });
        }

        if (btnPhish) {
            btnPhish.addEventListener("click", () => {
                state.emailVerdict = "phish";
                showEmailVerdictFeedback(true);
            });
        }
    }

    function showEmailVerdictFeedback(isCorrectVerdict) {
        const feedbackBox = document.getElementById("verdict-feedback");
        if (!feedbackBox) return;

        feedbackBox.classList.remove("hidden");
        
        // SECURITY FIX [F2]: Build feedback DOM with safe APIs instead of innerHTML
        // Clear existing content
        while (feedbackBox.firstChild) {
            feedbackBox.removeChild(feedbackBox.firstChild);
        }

        if (isCorrectVerdict) {
            feedbackBox.className = "feedback-toast success";
            
            const h5 = document.createElement('h5');
            h5.textContent = '✓ VERDICT CORRECT: SECURE ANALYSIS MATCH';
            feedbackBox.appendChild(h5);

            const p = document.createElement('p');
            p.textContent = 'Excellent investigation! You correctly identified this as a phishing attempt. The spoofed domain, false urgency, lack of personal greeting, lookalike link, and double extension attachment are classic markers of business phishing. You have unlocked Module 3: Website Spotter.';
            feedbackBox.appendChild(p);

            const proceedBtn = document.createElement('button');
            proceedBtn.className = 'btn btn-primary';
            proceedBtn.style.marginTop = '1rem';
            proceedBtn.textContent = 'Proceed to Website Spotter →';
            proceedBtn.addEventListener('click', () => {
                switchTab("module-websites");
            });
            feedbackBox.appendChild(proceedBtn);
            
            // Progress unlock
            state.completedModules.email = true;
            state.unlockedModules.websites = true;
            calculateProgress();
        } else {
            feedbackBox.className = "feedback-toast error";

            const h5 = document.createElement('h5');
            h5.textContent = '✗ VERDICT INCORRECT: MALICIOUS THREAT UNDETECTED';
            feedbackBox.appendChild(h5);

            const p = document.createElement('p');
            p.textContent = 'Warning! Classifying this email as Safe leaves you vulnerable. Review the unlocked finding cards on the right. Notice how the domain uses typosquatting (paypa1) and the invoice attachment ends in a dangerous extension (.exe). Take another look at the clues before proceeding.';
            feedbackBox.appendChild(p);
        }
    }

    // ==========================================================================
    // MODULE 3: WEBSITE SPOTTER
    // ==========================================================================
    function setupWebsiteSpotter() {
        const btnSiteA = document.getElementById("btn-site-a");
        const btnSiteB = document.getElementById("btn-site-b");
        const verdictSiteA = document.getElementById("verdict-site-a");
        const verdictSiteB = document.getElementById("verdict-site-b");
        
        if (btnSiteA && btnSiteB) {
            btnSiteA.addEventListener("click", () => selectSimulatedSite('A'));
            btnSiteB.addEventListener("click", () => selectSimulatedSite('B'));
        }

        if (verdictSiteA) {
            verdictSiteA.addEventListener("click", () => checkSiteVerdict('A'));
        }
        
        if (verdictSiteB) {
            verdictSiteB.addEventListener("click", () => checkSiteVerdict('B'));
        }
        
        // Cert details button
        const btnCert = document.getElementById("btn-cert-detail");
        if (btnCert) {
            btnCert.addEventListener("click", () => {
                if (state.currentSelectedSite === 'A') {
                    alert("SSL Certificate Status:\nIssued to: netflix.com\nCA Authority: DigiCert TLS RSA SHA256 2020 CA1\nStatus: Secure & Valid");
                } else {
                    alert("SSL Certificate Status:\nIssued to: netf1ix-login-verify.com\nCA Authority: Free Let's Encrypt Authority\nStatus: The certificate is active, but the domain registration is registered to an unknown entity and is only 2 days old. Highly suspicious.");
                }
            });
        }
    }

    function selectSimulatedSite(siteVersion) {
        state.currentSelectedSite = siteVersion;
        
        const btnSiteA = document.getElementById("btn-site-a");
        const btnSiteB = document.getElementById("btn-site-b");
        
        // Address bar elements
        const addrBar = document.querySelector(".browser-address-bar");
        const protocol = document.getElementById("address-protocol");
        const domain = document.getElementById("address-domain");
        const path = document.getElementById("address-path");
        
        if (siteVersion === 'A') {
            btnSiteA.classList.add("active");
            btnSiteB.classList.remove("active");
            
            addrBar.classList.remove("danger");
            protocol.textContent = "https://";
            domain.textContent = "www.netflix.com";
            path.textContent = "/login";
        } else {
            btnSiteA.classList.remove("active");
            btnSiteB.classList.add("active");
            
            addrBar.classList.add("danger");
            protocol.textContent = "http://";
            domain.textContent = "www.netf1ix-login-verify.com";
            path.textContent = "/signin";
        }
    }

    function checkSiteVerdict(chosenSite) {
        const feedbackText = document.getElementById("site-feedback");
        if (!feedbackText) return;
        
        feedbackText.classList.remove("hidden");

        // SECURITY FIX [F2]: Build feedback DOM with safe APIs instead of innerHTML
        while (feedbackText.firstChild) {
            feedbackText.removeChild(feedbackText.firstChild);
        }
        
        if (chosenSite === 'B') {
            feedbackText.className = "site-feedback-message success";

            const strong = document.createElement('strong');
            strong.textContent = 'Correct! Website B is a fraudulent clone.';
            feedbackText.appendChild(strong);
            feedbackText.appendChild(document.createElement('br'));

            const reasons = document.createDocumentFragment();
            const r1 = document.createTextNode('Reasons:');
            reasons.appendChild(r1);
            reasons.appendChild(document.createElement('br'));

            const r2 = document.createTextNode('1. The connection protocol is unsecure (http:// instead of https://).');
            reasons.appendChild(r2);
            reasons.appendChild(document.createElement('br'));

            const r3 = document.createTextNode('2. The domain is netf1ix-login-verify.com. Attackers buy lookalike domains with spelling variations (using \'1\' instead of \'l\') to spoof official brand pages.');
            reasons.appendChild(r3);
            reasons.appendChild(document.createElement('br'));

            const r4 = document.createTextNode('You have successfully completed this module and unlocked the assessment quiz!');
            reasons.appendChild(r4);

            feedbackText.appendChild(reasons);

            const proceedBtn = document.createElement('button');
            proceedBtn.className = 'btn btn-primary';
            proceedBtn.style.marginTop = '1rem';
            proceedBtn.style.display = 'block';
            proceedBtn.textContent = 'Start Scenario Quiz →';
            proceedBtn.addEventListener('click', () => {
                switchTab("module-quiz");
            });
            feedbackText.appendChild(proceedBtn);
            
            state.completedModules.websites = true;
            state.unlockedModules.quiz = true;
            calculateProgress();
        } else {
            feedbackText.className = "site-feedback-message error";

            const strong = document.createElement('strong');
            strong.textContent = 'Incorrect. Website A is the genuine Netflix portal.';
            feedbackText.appendChild(strong);
            feedbackText.appendChild(document.createElement('br'));

            const hint = document.createTextNode('Take another look. Notice that Website A uses https:// with a valid padlock and points to the official www.netflix.com domain. Check Site Version B to inspect domain anomalies.');
            feedbackText.appendChild(hint);
        }
    }

    // ==========================================================================
    // MODULE 4: SCENARIO QUIZ
    // ==========================================================================
    function setupQuiz() {
        const btnStart = document.getElementById("start-quiz-btn");
        const btnRetry = document.getElementById("btn-retry-quiz");
        const btnReview = document.getElementById("btn-review-modules");
        
        if (btnStart) {
            btnStart.addEventListener("click", startQuiz);
        }
        
        if (btnRetry) {
            btnRetry.addEventListener("click", startQuiz);
        }
        
        if (btnReview) {
            btnReview.addEventListener("click", () => {
                switchTab("dashboard");
            });
        }

        const btnNext = document.getElementById("btn-next-question");
        if (btnNext) {
            btnNext.addEventListener("click", nextQuestion);
        }

        // Name entry submission for certificate
        const btnGenCert = document.getElementById("btn-generate-cert");
        if (btnGenCert) {
            btnGenCert.addEventListener("click", () => {
                const nameInput = document.getElementById("cert-user-name");
                const rawValue = nameInput ? nameInput.value.trim() : "";

                // SECURITY FIX [F7]: Validate name with regex before using
                if (!NAME_REGEX.test(rawValue)) {
                    alert("Please enter a valid name (2-100 characters, letters, spaces, hyphens, periods, and apostrophes only).");
                    return;
                }

                state.userName = rawValue;
                renderCertificate();
                
                // Show certificate panel
                document.getElementById("quiz-result").classList.add("hidden");
                document.getElementById("certificate-screen").classList.remove("hidden");
            });
        }

        // Certificate Actions
        const btnPrint = document.getElementById("btn-print-cert");
        if (btnPrint) {
            btnPrint.addEventListener("click", () => {
                window.print();
            });
        }

        const btnRestart = document.getElementById("btn-restart-portal");
        if (btnRestart) {
            btnRestart.addEventListener("click", () => {
                // Reset to dashboard
                switchTab("dashboard");
            });
        }
    }

    function startQuiz() {
        state.quizStarted = true;
        state.currentQuestionIndex = 0;
        state.quizScore = 0;
        state.quizAnswers = [];
        
        document.getElementById("quiz-intro").classList.add("hidden");
        document.getElementById("quiz-result").classList.add("hidden");
        document.getElementById("quiz-active").classList.remove("hidden");
        
        loadQuizQuestion();
    }

    function loadQuizQuestion() {
        const question = quizQuestions[state.currentQuestionIndex];
        
        // Update HUD
        document.getElementById("current-q-num").textContent = state.currentQuestionIndex + 1;
        const progressFill = document.getElementById("q-progress-fill");
        if (progressFill) {
            progressFill.style.width = `${((state.currentQuestionIndex + 1) / quizQuestions.length) * 100}%`;
        }
        
        // Load Question Info
        document.getElementById("question-icon").textContent = question.icon;
        document.getElementById("question-title").textContent = question.title;
        document.getElementById("question-context").textContent = question.context;
        
        // Hide explanation box
        document.getElementById("quiz-explanation").classList.add("hidden");
        
        // SECURITY FIX [F2]: Build options with safe DOM APIs instead of innerHTML
        const optionsContainer = document.getElementById("quiz-options-container");
        while (optionsContainer.firstChild) {
            optionsContainer.removeChild(optionsContainer.firstChild);
        }
        
        question.options.forEach((opt, idx) => {
            const btn = document.createElement("button");
            btn.className = "option-btn";
            btn.textContent = opt.text; // SECURITY FIX [F2]: textContent instead of innerHTML
            btn.addEventListener("click", () => submitQuizAnswer(idx));
            optionsContainer.appendChild(btn);
        });
    }

    function submitQuizAnswer(optionIndex) {
        // Disable all options
        const optionButtons = document.querySelectorAll("#quiz-options-container .option-btn");
        optionButtons.forEach(btn => {
            btn.disabled = true;
        });

        const question = quizQuestions[state.currentQuestionIndex];
        const selectedOpt = question.options[optionIndex];
        const explanationBox = document.getElementById("quiz-explanation");
        const explanationHeader = document.getElementById("explanation-header");
        const explanationText = document.getElementById("explanation-text");

        // Check correction
        if (selectedOpt.correct) {
            state.quizScore++;
            optionButtons[optionIndex].classList.add("correct-choice");
            explanationBox.className = "quiz-explanation-box success";
            explanationHeader.textContent = "✓ Correct Decision";
        } else {
            optionButtons[optionIndex].classList.add("incorrect-choice");
            explanationBox.className = "quiz-explanation-box error";
            explanationHeader.textContent = "✗ Threat Compromise";
            
            // Highlight correct option
            question.options.forEach((opt, idx) => {
                if (opt.correct) {
                    optionButtons[idx].classList.add("correct-choice");
                }
            });
        }

        explanationText.textContent = selectedOpt.explanation;
        explanationBox.classList.remove("hidden");
    }

    function nextQuestion() {
        state.currentQuestionIndex++;
        if (state.currentQuestionIndex < quizQuestions.length) {
            loadQuizQuestion();
        } else {
            showQuizResults();
        }
    }

    function showQuizResults() {
        document.getElementById("quiz-active").classList.add("hidden");
        const resultPanel = document.getElementById("quiz-result");
        resultPanel.classList.remove("hidden");

        // SECURITY FIX [F2]: Build score badge with safe DOM APIs
        const badgeWrap = document.getElementById("result-badge-wrap");
        const pct = state.quizScore / quizQuestions.length;
        const isPass = pct >= 0.8; // 80% passing grade
        const circumference = 2 * Math.PI * 50; // Radius = 50
        const offset = circumference - (pct * circumference);
        const strokeColor = isPass ? "var(--color-green)" : "var(--color-red)";

        // Clear existing content safely
        while (badgeWrap.firstChild) {
            badgeWrap.removeChild(badgeWrap.firstChild);
        }

        const svgNS = "http://www.w3.org/2000/svg";
        const svg = document.createElementNS(svgNS, "svg");
        svg.setAttribute("viewBox", "0 0 120 120");

        const circleBg = document.createElementNS(svgNS, "circle");
        circleBg.setAttribute("class", "circle-bg");
        circleBg.setAttribute("cx", "60");
        circleBg.setAttribute("cy", "60");
        circleBg.setAttribute("r", "50");
        svg.appendChild(circleBg);

        const circleVal = document.createElementNS(svgNS, "circle");
        circleVal.setAttribute("class", "circle-val");
        circleVal.setAttribute("cx", "60");
        circleVal.setAttribute("cy", "60");
        circleVal.setAttribute("r", "50");
        circleVal.setAttribute("stroke", strokeColor);
        circleVal.setAttribute("stroke-dasharray", circumference.toString());
        circleVal.setAttribute("stroke-dashoffset", offset.toString());
        svg.appendChild(circleVal);

        badgeWrap.appendChild(svg);

        const scoreSpan = document.createElement("span");
        scoreSpan.className = "circular-score";
        scoreSpan.style.color = strokeColor;
        scoreSpan.textContent = `${state.quizScore}/${quizQuestions.length}`;
        badgeWrap.appendChild(scoreSpan);

        // Headlines
        const resultHeadline = document.getElementById("result-headline");
        const resultSummary = document.getElementById("result-summary-text");
        const passActions = document.getElementById("quiz-pass-actions");
        const failActions = document.getElementById("quiz-fail-actions");

        if (isPass) {
            resultHeadline.textContent = "Shield Evaluation Passed!";
            resultHeadline.style.color = "var(--color-green)";
            resultSummary.textContent = "Congratulations! You correctly resolved the social engineering threats. Enter your name below to obtain your training completion certificate.";
            
            passActions.classList.remove("hidden");
            failActions.classList.add("hidden");

            // Set Quiz module as completed
            state.completedModules.quiz = true;
            calculateProgress();
        } else {
            resultHeadline.textContent = "Shield Evaluation Failed";
            resultHeadline.style.color = "var(--color-red)";
            resultSummary.textContent = `You scored ${state.quizScore} out of ${quizQuestions.length}. A minimum score of 4/5 is required to establish phishing defense competency and unlock the certificate.`;
            
            passActions.classList.add("hidden");
            failActions.classList.remove("hidden");
        }
    }

    // ==========================================================================
    // DYNAMIC SVG CERTIFICATE RENDERER
    // ==========================================================================
    function renderCertificate() {
        const certContainer = document.getElementById("cert-canvas-container");
        if (!certContainer) return;

        const dateOptions = { year: 'numeric', month: 'long', day: 'numeric' };
        const dateStr = new Date().toLocaleDateString("en-US", dateOptions);

        // SECURITY FIX [F1]: Sanitize user name before inserting into SVG template
        const safeName = escapeHTML(state.userName.toUpperCase());
        const safeDate = escapeHTML(dateStr);

        const svgCert = `
            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 800 550" width="100%" height="100%">
                <defs>
                    <linearGradient id="goldGrad" x1="0%" y1="0%" x2="100%" y2="100%">
                        <stop offset="0%" stop-color="#bf953f" />
                        <stop offset="25%" stop-color="#fcf6ba" />
                        <stop offset="50%" stop-color="#b38728" />
                        <stop offset="75%" stop-color="#fbf5b7" />
                        <stop offset="100%" stop-color="#aa771c" />
                    </linearGradient>
                    <linearGradient id="darkBg" x1="0%" y1="0%" x2="0%" y2="100%">
                        <stop offset="0%" stop-color="#0f172a" />
                        <stop offset="100%" stop-color="#020617" />
                    </linearGradient>
                </defs>

                <!-- Background Card -->
                <rect width="800" height="550" rx="12" fill="url(#darkBg)" stroke="url(#goldGrad)" stroke-width="6"/>
                
                <!-- Interior Decorative Border -->
                <rect x="20" y="20" width="760" height="510" rx="8" fill="none" stroke="rgba(251, 245, 183, 0.2)" stroke-width="2" stroke-dasharray="10 5"/>
                <rect x="30" y="30" width="740" height="490" rx="6" fill="none" stroke="rgba(251, 245, 183, 0.1)" stroke-width="1"/>

                <!-- Header logo/brand -->
                <g transform="translate(400, 85)" text-anchor="middle">
                    <!-- Shield Icon -->
                    <path d="M-12 -20 L12 -20 L18 -2 V8 C18 18 0 25 0 25 C0 25 -18 18 -18 8 V-2 Z" fill="none" stroke="url(#goldGrad)" stroke-width="2.5"/>
                    <path d="M0 -12 L6 -8 V3 C6 8 0 12 0 12 C0 12 -6 8 -6 3 V-8 Z" fill="url(#goldGrad)"/>
                    <text y="42" font-family="'Space Grotesk', sans-serif" font-size="14" fill="#94a3b8" letter-spacing="3" font-weight="700">CYBERSHIELD DEFENSE INITIATIVE</text>
                </g>

                <!-- Title -->
                <text x="400" y="200" text-anchor="middle" font-family="'Space Grotesk', sans-serif" font-size="34" font-weight="700" fill="url(#goldGrad)">CERTIFICATE OF COMPETENCY</text>
                <text x="400" y="235" text-anchor="middle" font-family="'Inter', sans-serif" font-size="14" fill="#94a3b8" font-style="italic">This credential verifies that the recipient has demonstrated phishing recognition capability</text>

                <!-- Awardee Name (SECURITY FIX [F1]: HTML-escaped user input) -->
                <text x="400" y="305" text-anchor="middle" font-family="'Space Grotesk', sans-serif" font-size="38" font-weight="700" fill="#ffffff" letter-spacing="1">${safeName}</text>
                <line x1="200" y1="320" x2="600" y2="320" stroke="url(#goldGrad)" stroke-width="2"/>

                <!-- Scope -->
                <text x="400" y="355" text-anchor="middle" font-family="'Inter', sans-serif" font-size="13" fill="#94a3b8">has successfully completed the interactive security curriculum focusing on:</text>
                <text x="400" y="378" text-anchor="middle" font-family="'Inter', sans-serif" font-size="14" fill="#f8fafc" font-weight="600">Email Vector Analysis • Spoofed Website Detection • Social Engineering Defense</text>

                <!-- Signatures -->
                <g transform="translate(150, 460)" text-anchor="middle">
                    <line x1="-80" y1="0" x2="80" y2="0" stroke="#334155" stroke-width="1.5"/>
                    <text y="15" font-family="'Inter', sans-serif" font-size="11" fill="#64748b">DATE OF ISSUANCE</text>
                    <text y="-8" font-family="'Space Grotesk', sans-serif" font-size="13" fill="#ffffff" font-weight="600">${safeDate}</text>
                </g>

                <g transform="translate(650, 460)" text-anchor="middle">
                    <!-- Signature line -->
                    <path d="M-50 -10 Q-30 -25 -10 -5 T30 -20 T50 -10" fill="none" stroke="rgba(251, 245, 183, 0.4)" stroke-width="2" stroke-linecap="round"/>
                    <line x1="-80" y1="0" x2="80" y2="0" stroke="#334155" stroke-width="1.5"/>
                    <text y="15" font-family="'Inter', sans-serif" font-size="11" fill="#64748b">CHIEF SECURITY OFFICER</text>
                    <text y="-8" font-family="'Space Grotesk', sans-serif" font-size="12" fill="#ffffff" font-weight="600">CyberShield Academy</text>
                </g>

                <!-- Bottom Border seal -->
                <circle cx="400" cy="460" r="32" fill="none" stroke="url(#goldGrad)" stroke-width="2"/>
                <circle cx="400" cy="460" r="27" fill="none" stroke="url(#goldGrad)" stroke-width="1" stroke-dasharray="4 2"/>
                <path d="M400 440 L412 455 H388 Z" fill="url(#goldGrad)"/>
                <path d="M400 480 L388 465 H412 Z" fill="url(#goldGrad)"/>
            </svg>
        `;

        certContainer.innerHTML = svgCert;
    }

})(); // End IIFE (SECURITY FIX [F8])
