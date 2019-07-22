import React from "react";

import PropTypes from 'prop-types';

import MenuplanListItem from './MenuplanListItem';

// eslint-disable-next-line no-unused-vars
import log from 'Log';


class MenuplanList extends React.Component {
    constructor(props) {
        super(props);
        this.state = {
        };
    }

    render() {
        const items = this.props.items,
            d = new Date(),
            n = d.getDay();

        switch (n) {
            case 1:
                return (
                    <div className="tickercontainer">
                        <div className="mask">
                            <div className="menuplan-teaser-items-container">
                                <div className="row">
                                    <div className="col-12">
                                        <h3>Montag</h3>
                                    </div>
                                </div>
                                <div className="row">
                                    {items.map((item) =>
                                        <MenuplanListItem key={item.uniq_id.toString()} value={item} weekday="0"
                                        />
                                    )}
                                </div>
                            </div>
                        </div>
                    </div>
                );
            case 2:
                return (
                    <div className="tickercontainer">
                        <div className="mask">
                            <div className="menuplan-teaser-items-container">
                                <div className="row">
                                    <div className="col-12">
                                        <h3>Dienstag</h3>
                                    </div>
                                </div>
                                <div className="row">
                                    {items.map((item) =>
                                        <MenuplanListItem key={item.uniq_id.toString()} value={item} weekday="1"
                                        />
                                    )}
                                </div>
                            </div>
                        </div>
                    </div>
                );
            case 3:
                return (
                    <div className="tickercontainer">
                        <div className="mask">
                            <div className="menuplan-teaser-items-container">
                                <div className="row">
                                    <div className="col-12">
                                        <h3>Mittwoch</h3>
                                    </div>
                                </div>
                                <div className="row">
                                    {items.map((item) =>
                                        <MenuplanListItem key={item.uniq_id.toString()} value={item} weekday="2"
                                        />
                                    )}
                                </div>
                            </div>
                        </div>
                    </div>
                );
            case 4:
                return (
                    <div className="tickercontainer">
                        <div className="mask">
                            <div className="menuplan-teaser-items-container">
                                <div className="row">
                                    <div className="col-12">
                                        <h3>Donnerstag</h3>
                                    </div>
                                </div>
                                <div className="row">
                                    {items.map((item) =>
                                        <MenuplanListItem key={item.uniq_id.toString()} value={item} weekday="3"
                                        />
                                    )}
                                </div>
                            </div>
                        </div>
                    </div>
                );
            case 5:
                return (
                    <div className="tickercontainer">
                        <div className="mask">
                            <div className="menuplan-teaser-items-container">
                                <div className="row">
                                    <div className="col-12">
                                        <h3>Freitag</h3>
                                    </div>
                                </div>
                                <div className="row">
                                    {items.map((item) =>
                                        <MenuplanListItem key={item.uniq_id.toString()} value={item} weekday="4"
                                        />
                                    )}
                                </div>
                            </div>
                        </div>
                    </div>
                );
            default:
                return (
                    <div className="menuplan-teaser-items-container">
                    </div>
                );
        }
    }
}

MenuplanList.propTypes = {
    items: PropTypes.array.isRequired,
};

export default MenuplanList;