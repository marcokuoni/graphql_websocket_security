import React from "react";

import PropTypes from 'prop-types';

import { withStyles } from '@material-ui/core/styles';

// eslint-disable-next-line no-unused-vars
import log from 'Log';

class SolaranlageItem extends React.Component {
    constructor(props) {
        super(props);
        this.state = {
            height: 0,
            width: 0,
            imgWidth: 0,
            workloadHeight: 0,
            lineHeight: 0,
        };
    }

    componentDidMount() {
        this.setState({
            height: document.getElementById('solaranlage-image-wrapper').clientHeight,
            width: document.getElementById('solaranlage-image-wrapper').clientWidth,
            imgWidth: document.getElementById('solaranlage-img').clientWidth,
            workloadHeight: document.getElementById('current-workload').clientHeight,
            lineHeight: document.getElementById('line').clientHeight,
        });
    }

    render() {
        const offset = Math.round(this.state.height / 100 * (100 - this.props.item.workload));

        return (
            <div className="item-wrapper-wrapper">
                <div className="row">
                    <div className="col-8">
                        <div className="row">
                            <div className="col-12">
                                <h2>Stromproduktion im HPZ <span className="live">(Live)</span></h2>
                            </div>
                            <div className="col-12">
                                <div id="solaranlage-image-wrapper" className="solaranlage-image-wrapper">
                                    <img className="solaranlage" src="/packages/hpzgl/themes/hpzgl/images/solar_1_beige.svg" alt="HPZ Solaranlage" />
                                    <div className="crop" style={{top: `${offset}px`, height: `${this.state.height - offset}px`}}>
                                        <img id="solaranlage-img" className="" src="/packages/hpzgl/themes/hpzgl/images/solar_2_orange.svg" alt="HPZ Solaranlage" style={{marginTop: `${-offset}px`}}/>
                                    </div>
                                    <div id="current-workload" className="current-workload main-value-font orange" style={{top: `${offset - this.state.workloadHeight}px`}}>{`${this.props.item.workload} %`}</div>
                                    <div id="line" className="line" style={{width: `${this.state.width - this.state.imgWidth}px`, top: `${offset}px`}}></div>
                                    <img className="solaranlage" src="/packages/hpzgl/themes/hpzgl/images/solar_3_fenster.svg" alt="HPZ Solaranlage" />
                                    <p className="suplement" style={{top: `${offset + this.state.lineHeight + 5}px`}}><span className="lead bold darkest-grey">Auslastung</span><br />der Solaranlage</p>
                                </div>
                            </div>
                        </div>
                    </div>
                    <div className="col-1"></div>
                    <div className="col-3">
                        <div className="row second-value-row">
                            <div className="col-12">
                                <div className="value1 value-font middle-grey"><span className="value">{this.props.item.value1}</span> KW</div>
                                <p><span className="bold darkest-grey">Leistung Aktuell</span></p>
                            </div>
                            <div className="col-12">
                                <div className="value2 value-font middle-grey"><span className="value">{this.props.item.value2}</span> KW</div>
                                <p><span className="bold darkest-grey">Tagesleistung</span></p>
                            </div>
                            <div className="col-12">
                                <div className="value3 value-font middle-grey"><span className="value">{this.props.item.value3}</span> MW</div>
                                <p><span className="bold darkest-grey">Jahresleistung</span></p>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        );
    }
}

SolaranlageItem.propTypes = {
    item: PropTypes.object.isRequired,
};

export default SolaranlageItem;