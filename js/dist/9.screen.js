(window.webpackJsonp=window.webpackJsonp||[]).push([[9],{426:function(e,t,n){"use strict";n.r(t);var o=n(10),r=n.n(o),a=n(363),i=n.n(a),u=n(353),c=n(348),l=n.n(c),s=n(360),f=n(436),p=n(30);n(34);function d(e){return(d="function"==typeof Symbol&&"symbol"==typeof Symbol.iterator?function(e){return typeof e}:function(e){return e&&"function"==typeof Symbol&&e.constructor===Symbol&&e!==Symbol.prototype?"symbol":typeof e})(e)}function y(e,t){for(var n=0;n<t.length;n++){var o=t[n];o.enumerable=o.enumerable||!1,o.configurable=!0,"value"in o&&(o.writable=!0),Object.defineProperty(e,o.key,o)}}function b(e){return(b=Object.setPrototypeOf?Object.getPrototypeOf:function(e){return e.__proto__||Object.getPrototypeOf(e)})(e)}function m(e){if(void 0===e)throw new ReferenceError("this hasn't been initialised - super() hasn't been called");return e}function g(e,t){return(g=Object.setPrototypeOf||function(e,t){return e.__proto__=t,e})(e,t)}function v(e,t,n){return t in e?Object.defineProperty(e,t,{value:n,enumerable:!0,configurable:!0,writable:!0}):e[t]=n,e}function h(){var e=function(e,t){t||(t=e.slice(0));return Object.freeze(Object.defineProperties(e,{raw:{value:Object.freeze(t)}}))}(["\n  query {\n    getMultimediaItem {\n        item_id\n        youtube_link\n        text\n      }\n  }\n"]);return h=function(){return e},e}var w=i()(h()),j=function(e){function t(e){var n,o,r;return function(e,t){if(!(e instanceof t))throw new TypeError("Cannot call a class as a function")}(this,t),o=this,r=b(t).call(this,e),n=!r||"object"!==d(r)&&"function"!=typeof r?m(o):r,v(m(n),"youtubeGetID",function(e){return void 0!==(e=e.split(/(vi\/|v=|\/v\/|youtu\.be\/|\/embed\/)/))[2]?e[2].split(/[^0-9a-z_\-]/i)[0]:e[0]}),v(m(n),"isFunction",function(e){return e&&"[object Function]"==={}.toString.call(e)}),v(m(n),"onStateChange",function(e){e.data==YT.PlayerState.ENDED&&n.isFunction(e.target.stopVideo)&&(e.target.stopVideo(),setTimeout(function(){e.target.playVideo()},1e3))}),n.state={},n.onStateChange=n.onStateChange.bind(m(n)),n.onReady=n.onReady.bind(m(n)),n}var n,o,a;return function(e,t){if("function"!=typeof t&&null!==t)throw new TypeError("Super expression must either be null or a function");e.prototype=Object.create(t&&t.prototype,{constructor:{value:e,writable:!0,configurable:!0}}),t&&g(e,t)}(t,r.a.Component),n=t,(o=[{key:"onReady",value:function(e){e.target.mute(),e.target.playVideo()}},{key:"render",value:function(){var e=this,t=String(window.location.protocol+"//"+window.location.host),n=this.props.classes,o={height:"408",width:"659",origin:encodeURIComponent(t),playerVars:{autoplay:1,controls:0},enablejsapi:1};return r.a.createElement("div",{className:n.root},r.a.createElement(u.b,{query:w,pollInterval:p.a.defaultPollIntervall},function(t){var n=t.loading,a=t.error,i=t.data;return n?"Loading...":a?"Error! ".concat(a.message):r.a.createElement("div",null,i&&i.getMultimediaItem.map(function(t){return r.a.createElement("div",{key:t.item_id},r.a.createElement("div",{key:t.item_id,className:"item background-video background-image"},r.a.createElement(f.a,{videoId:e.youtubeGetID(t.youtube_link),opts:o,onReady:e.onReady,onStateChange:e.onStateChange})),r.a.createElement("h3",{className:"word-container"},t.text))}))}))}}])&&y(n.prototype,o),a&&y(n,a),t}();j.propTypes={classes:l.a.object.isRequired},t.default=Object(s.withStyles)(function(e){return{root:{flexGrow:1},paper:{padding:2*e.spacing.unit,textAlign:"center",color:e.palette.text.secondary}}})(j)}}]);
//# sourceMappingURL=9.screen.js.map