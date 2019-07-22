import React from "react";
import gql from "graphql-tag";
import { Query } from "react-apollo";

import PropTypes from 'prop-types';

import { withStyles } from '@material-ui/core/styles';

import MenuplanList from './MenuplanList';

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

class Menuplan extends React.Component {
    constructor(props) {
        super(props);
        this.state = {
        };
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
                }
            },
            GET_MENUPLAN_ITEM = gql`
query {
    getMenuplanItem {
        item_id
        uniq_id
        title
        weekday
        image_source_url
        image_url
        image_url_2x
    }
}
`;

        return (
            <div className={classes.root}>
                <h2 className="main-title">Menü</h2>
                <Query
                    query={GET_MENUPLAN_ITEM}
                    pollInterval={configMap.defaultPollIntervall}
                >
                    {({ loading, error, data }) => {
                        if (loading) return "Loading...";
                        if (error) return `Error! ${error.message}`;

                        return (
                            <div>
                                {
                                    data && (
                                        <MenuplanList items={data.getMenuplanItem} />
                                    )
                                }
                            </div>
                        );
                    }}
                </Query>
            </div>
        );
    }
}

Menuplan.propTypes = {
    classes: PropTypes.object.isRequired,
};

export default withStyles(styles)(Menuplan);