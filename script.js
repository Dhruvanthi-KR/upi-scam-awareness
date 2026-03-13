function checkLink() {
    let link = document.getElementById("linkInput").value;
    let result = document.getElementById("result");

    let suspiciousWords = [
        "reward",
        "cashback",
        "free",
        "receive",
        "money",
        "bonus",
        ".xyz",
        ".click",
        ".top",
    ];

    let isScam = false;

    for (let i = 0; i < suspiciousWords.length; i++) {
        if (link.includes(suspiciousWords[i])) {
            isScam = true;
            break;
        }
    }

    if (isScam) {
        result.innerHTML = "⚠ This link looks suspicious. It may be a scam.";
        result.style.color = "red";
    } else {
        result.innerHTML =
            "✔ This link looks safer but still verify before clicking.";
        result.style.color = "green";
    }
}

function correct(){
document.getElementById("quizResult").innerHTML =
"✔ Correct! UPI PIN should only be entered inside official apps.";
}

function wrong(){
document.getElementById("quizResult").innerHTML =
"❌ Wrong! Never enter your UPI PIN on websites.";
}