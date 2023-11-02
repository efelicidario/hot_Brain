const user_id = document.getElementById('user-id').textContent;
var nextButton = document.getElementById("next");


video.addEventListener("play", (event) => {
    play_start(user_id, 0)
});

// For when the video ends
video.addEventListener("ended", (event) => {
    stop_movie(user_id, 0);
    nextButton.style.display = "block";
});