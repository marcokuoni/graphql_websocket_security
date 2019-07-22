import React from "react";
import gql from "graphql-tag";
import { Query } from "react-apollo";

import PropTypes from 'prop-types';

import { withStyles } from '@material-ui/core/styles';

import YouTube from 'react-youtube';

import configMap from 'Utilities/GetGlobals';
// eslint-disable-next-line no-unused-vars
import log from 'Log';

const styles = theme => ({
    root: {
        flexGrow: 1,
    },
    paper: {
        padding: theme.spacing.unit * 2,
        textAlign: 'center',
        color: theme.palette.text.secondary,
    },
});


const GET_MULTIMEDIA_ITEM = gql`
  query {
    getMultimediaItem {
        item_id
        youtube_link
        text
      }
  }
`;

class Multimedia extends React.Component {
    constructor(props) {
        super(props);
        this.state = {
        };

        this.onStateChange = this.onStateChange.bind(this);
        this.onReady = this.onReady.bind(this);
    }

    youtubeGetID = function (url) {
        url = url.split(/(vi\/|v=|\/v\/|youtu\.be\/|\/embed\/)/);
        return (url[2] !== undefined) ? url[2].split(/[^0-9a-z_\-]/i)[0] : url[0];
    };

    isFunction = function (functionToCheck) {
        return functionToCheck && {}.toString.call(functionToCheck) === '[object Function]';
    }

    onReady(event) {
        event.target.mute();
        event.target.playVideo();
    }

    onStateChange = (event) => {
        if (event.data == YT.PlayerState.ENDED) {
            if (this.isFunction(event.target.stopVideo)) {
                event.target.stopVideo();
                setTimeout(function () {
                    event.target.playVideo();
                }, 1000);
            }
        }
    }

    render() {
        const originSrc = String(window.location.protocol + "//" + window.location.host),
            { classes } = this.props,
            opts = {
                height: '408',
                width: '659',
                origin: encodeURIComponent(originSrc),
                playerVars: { // https://developers.google.com/youtube/player_parameters
                    autoplay: 1,
                    controls: 0
                },
                enablejsapi: 1,
            };

        return (
            <div className={classes.root}>
                <Query
                    query={GET_MULTIMEDIA_ITEM}
                    pollInterval={configMap.defaultPollIntervall}
                >
                    {({ loading, error, data }) => {
                        if (loading) return "Loading...";
                        if (error) return `Error! ${error.message}`;

                        return (
                            <div>
                                {
                                    data && data.getMultimediaItem.map((multimediaItem) => (
                                        <div key={multimediaItem.item_id}>
                                            <div key={multimediaItem.item_id} className="item background-video background-image">
                                                <YouTube
                                                    videoId={this.youtubeGetID(multimediaItem.youtube_link)}
                                                    opts={opts}
                                                    onReady={this.onReady}
                                                    onStateChange={this.onStateChange}
                                                />
                                            </div>
                                            <h3 className="word-container">{multimediaItem.text}</h3>
                                        </div>
                                    ))
                                }
                            </div>
                        );
                    }}
                </Query>
            </div>
        );
    }
}

Multimedia.propTypes = {
    classes: PropTypes.object.isRequired,
};

export default withStyles(styles)(Multimedia);