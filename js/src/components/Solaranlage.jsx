import React from "react";
import gql from "graphql-tag";
import { Query } from "react-apollo";

import PropTypes from 'prop-types';

import { withStyles } from '@material-ui/core/styles';

import configMap from 'Utilities/GetGlobals';
// eslint-disable-next-line no-unused-vars
import log from 'Log';
import SolaranlageItem from "./SolaranlageItem";

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


const GET_SOLARANLAGE_ITEM = gql`
  query {
    getSolaranlageItem {
        workload
        value1
        value2
        value3
      }
  }
`;

class Solaranlage extends React.Component {
    constructor(props) {
        super(props);
        this.state = {
        };
    }

    render() {
        const { classes } = this.props;

        return (
            <div className={classes.root}>
                <Query
                    query={GET_SOLARANLAGE_ITEM}
                    pollInterval={configMap.defaultPollIntervall}
                >
                    {({ loading, error, data }) => {
                        if (loading) return "Loading...";
                        if (error) return `Error! ${error.message}`;

                        return (
                            <div>
                                {
                                    data && (
                                        <SolaranlageItem item={data.getSolaranlageItem} />
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

Solaranlage.propTypes = {
    classes: PropTypes.object.isRequired,
};

export default withStyles(styles)(Solaranlage);