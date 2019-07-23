import React from "react";

import PropTypes from 'prop-types';

// eslint-disable-next-line no-unused-vars
import log from 'Log';

const Image = function (props) {
    return (
        <img src={props.value.image_url} data-rjs={props.value.image_url_2x} alt={props.value.title} />
    );
};

Image.propTypes = {
    value: PropTypes.object.isRequired,
};

class NewsListItem extends React.Component {
    constructor(props) {
        super(props);
        this.state = {
        };
    }

    render() {
        if (this.props.value.image_source_url !== '') {
            return (
                <div className="row">
                    <div className="col-8">
                        <h3>{this.props.value.title}</h3>
                        <div className="content lead" dangerouslySetInnerHTML={{ __html: this.props.value.text }} />
                    </div>
                    <div className="col-4">
                        <Image value={this.props.value} />
                    </div>
                    <div className="col-12"><hr /></div>
                </div>
            );
        } else {
            return (
                <div className="row">
                    <div className="col-12">
                        <h3>{this.props.value.title}</h3>
                        <div className="content lead" dangerouslySetInnerHTML={{ __html: this.props.value.text }} />
                    </div>
                    <div className="col-12"><hr /></div>
                </div>
            );
        }
    }
}

NewsListItem.propTypes = {
    value: PropTypes.object.isRequired,
};

export default NewsListItem;