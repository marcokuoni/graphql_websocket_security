import React from "react";
import ReactDOM from 'react-dom';
import loadable from '@loadable/component'

import configMap from 'Utilities/GetGlobals';
import SetConfigMap from 'Utilities/SetConfigMap';
import log from 'Log';

let isInited = false;

function Loading() {
    return <div>Loading...</div>;
}

const LoadableMultimediaComponent = loadable(() => import('./blocks/Multimedia'), {
    fallback: Loading,
});
const LoadableMenuplanComponent = loadable(() => import('./blocks/Menuplan'), {
    fallback: Loading,
});
const LoadableSolaranlageComponent = loadable(() => import('./blocks/Solaranlage'), {
    fallback: Loading,
});
const LoadableNewsComponent = loadable(() => import('./blocks/News'), {
    fallback: Loading,
});

window.screen = (function () {
    const configModule = function (input_map) {
        SetConfigMap({
            input_map: input_map,
            settable_map: configMap.settable_map,
            config_map: configMap
        });
    };

    const initModule = function (initItem) {
        switch (initItem) {
            case 'menuplan':
                ReactDOM.render(<LoadableMenuplanComponent />, document.querySelector('#menuplan-screen'));
                break;
            case 'multimedia':
                ReactDOM.render(<LoadableMultimediaComponent />, document.querySelector('#multimedia-screen'));
                break;
            case 'solaranlage':
                ReactDOM.render(<LoadableSolaranlageComponent />, document.querySelector('#solaranlage-screen'));
                break;
            case 'news':
                ReactDOM.render(<LoadableNewsComponent />, document.querySelector('#news-screen'));
                break;
        }

        if (!isInited) {
            log('It is running, jap', true);
            isInited = true;
        }
    };

    return {
        configModule: configModule,
        initModule: initModule
    };
}());