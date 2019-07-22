import React from "react";

import PropTypes from 'prop-types';

// eslint-disable-next-line no-unused-vars
import log from 'Log';


const Image = function (props) {
    return (
        <div className="img-wrapper">
            <img src={props.value.image_url} data-rjs={props.value.image_url_2x} alt={props.value.title} />
        </div>
    );
};

Image.propTypes = {
    value: PropTypes.object.isRequired,
};

class MenuplanListItem extends React.Component {
    constructor(props) {
        super(props);
        this.state = {
        };
    }

    render() {
        if (this.props.weekday === this.props.value.weekday) {
            if (this.props.value.image_source_url !== '') {
                return (
                    <div className="col-3">
                        <div className="row">
                            <div className="col-12">
                                <Image value={this.props.value} />
                            </div>
                            <div className="col-12">
                                <p className="title">{this.props.value.title}</p>
                            </div>
                        </div>
                    </div>
                );
            } else {
                return (
                    <div className="col-3">
                        <div className="row">
                            <div className="col-12">
                                <p className="title">{this.props.value.title}</p>
                            </div>
                        </div>
                    </div>
                );
            }
        } else {
            return '';
        }
    }
}

MenuplanListItem.propTypes = {
    weekday: PropTypes.string.isRequired,
    value: PropTypes.object.isRequired,
};

export default MenuplanListItem;