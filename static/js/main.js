function check_me(input_id){
  var checked_input = document.querySelector("input[id="+ input_id + "]");
  var checked_label = document.querySelector("label[for="+ input_id + "]");

  if (checked_input.checked){
    checked_label.style.textDecoration = "line-through";
  }
  else{
    checked_label.style.textDecoration = "";
  }
  
  // checked_label.style.textDecoration = checked_input.checked && "line-through" || ""; 

  var btn = document.getElementById("remove_btn");

  btn.value = "REMOVE ITEMS";
  btn.style.color = "#FFFFFF";
  btn.style.backgroundColor = "#FE7575";
  btn.style.cursor = "pointer";
}
