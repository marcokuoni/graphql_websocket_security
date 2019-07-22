import React from "react";
import gql from "graphql-tag";
import { Query } from "react-apollo";

import PropTypes from 'prop-types';

import { withStyles } from '@material-ui/core/styles';

import configMap from 'Utilities/GetGlobals';
// eslint-disable-next-line no-unused-vars
import log from 'Log';
import NewsList from "./NewsList";

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

class News extends React.Component {
    constructor(props) {
        super(props);
        this.state = {
        };
    }

    render() {
        const { classes } = this.props,
            GET_NEWS_ITEM = gql`
query {
    getNewsItem {
        item_id
        uniq_id
        date
        title
        text
        image_source_url
        image_url
        image_url_2x
    }
}
`;

        return (
            <div className={classes.root}>
                <h2 className="main-title">News</h2>
                <Query
                    query={GET_NEWS_ITEM}
                    pollInterval={configMap.defaultPollIntervall}
                >
                    {({ loading, error, data }) => {
                        if (loading) return "Loading...";
                        if (error) return `Error! ${error.message}`;

                        return (
                            <div>
                                {
                                    data && (
                                        <NewsList items={data.getNewsItem} />
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

News.propTypes = {
    classes: PropTypes.object.isRequired,
};

export default withStyles(styles)(News);