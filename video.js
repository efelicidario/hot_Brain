// Retrieve user ID and video ID from the placeholders
//const user_id = "GUEST";
function play_start(user_id, video_id){
    $.post("/open_api/play_movie", { "user_id": user_id, "video_id": 0},
        function(data, textStatus) {
            //this gets called when browser receives response from server
            console.log(data);
        }, "json").fail( function(response) {
            //this gets called if the server throws an error
            console.log("error");
        console.log(response);});
}

function stop_movie(user_id, video_id) {
$.post("/open_api/stop_movie", { "user_id": user_id, "video_id": 0 },
    function(data, textStatus) {
        // This gets called when the browser receives a response from the server
        console.log(data);

        }, "json").fail(function(response) {
    
            // This gets called if the server throws an error
            console.log("error");
            console.log(response);
        });
}