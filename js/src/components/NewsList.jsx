import React from "react";

import PropTypes from 'prop-types';

// eslint-disable-next-line no-unused-vars
import log from 'Log';
import NewsListItem from "./NewsListItem";


class NewsList extends React.Component {
    constructor(props) {
        super(props);
        this.state = {
        };
    }

    render() {
        const items = this.props.items;

        return (
            <div className="tickercontainer">
                <div className="mask">
                    <div className="news-items-container">

                        {items.map((item) =>
                            <NewsListItem key={item.uniq_id.toString()} value={item}
                            />
                        )}

                    </div>
                </div>
            </div>
        );
    }
}

NewsList.propTypes = {
    items: PropTypes.array.isRequired,
};

export default NewsList;