function update_buttons() {
	skin = 'skins/'+localStorage.skin ;
	document.getElementById('setup').src = skin+'/img/setup.png';
	if (localStorage.show=='') {
		document.getElementById('new_button').src = skin+'/img/new.png';
		document.getElementById('all_button').src = skin+'/img/all_selected.png';
	} else {
		document.getElementById('all_button').src = skin+'/img/all.png';
		document.getElementById('new_button').src = skin+'/img/new_selected.png';
	} 
}
function update_count(x) {
	document.getElementById('count').innerHTML=x ;
}

function toggle_visibility(obj) {
	var el = document.getElementById(obj);
	if ( el.className == 'visibleifpressed hide' ) {
		el.className = 'visibleifpressed show';
	} else {
		el.className = 'visibleifpressed hide';
	}
}

function  toggleClass(objClass){
  if (getElementByClass(objClass).style.display=="none"){
	showClass(objClass)
	localStorage.show="";
  }else{
	hideClass(objClass)
	localStorage.show="new";
  }
}

function hideClass(objClass){
var elements = document.getElementsByTagName('*');
  for (i=0; i<elements.length; i++){
    if (elements[i].className.match(objClass)){
      elements[i].style.display="none"
    }
  }
}

function showClass(objClass){
var elements = document.getElementsByTagName('*');
  for (i=0; i<elements.length; i++){
    if (elements[i].className.match(objClass)){
      elements[i].style.display="block"
    }
  }
}

function getElementByClass(objClass){
var elements = document.getElementsByTagName('*');
  for (i=0; i<elements.length; i++){
    if (elements[i].className.match(objClass)){
    	return elements[i];
    }
  }
}
function Select_Value_Set(SelectName, Value) {
	eval('SelectObject = document.' + SelectName + ';');
	for(index = 0; index < SelectObject.length; index++) {
		if ( SelectObject[index].value == Value ) {
			SelectObject.selectedIndex = index ;
		}
	}
}

