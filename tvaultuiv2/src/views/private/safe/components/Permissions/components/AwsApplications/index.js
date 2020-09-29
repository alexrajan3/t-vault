/* eslint-disable react/jsx-indent */
/* eslint-disable react/jsx-curly-newline */
import React, { useState, useEffect } from 'react';
import styled, { css } from 'styled-components';
import PropTypes from 'prop-types';
import useMediaQuery from '@material-ui/core/useMediaQuery';
import ComponentError from '../../../../../../../errorBoundaries/ComponentError/component-error';
import NoData from '../../../../../../../components/NoData';
import ButtonComponent from '../../../../../../../components/FormFields/ActionButton';
import PermissionsList from '../PermissionsList';
import noPermissionsIcon from '../../../../../../../assets/no-permissions.svg';
import mediaBreakpoints from '../../../../../../../breakpoints';
import apiService from '../../../../apiService';
import LoaderSpinner from '../../../../../../../components/Loaders/LoaderSpinner';
import Error from '../../../../../../../components/Error';
import AddAwsApplicationModal from '../../../AddAwsApplicationModal';

const { small } = mediaBreakpoints;

const NoDataWrapper = styled.section`
  display: flex;
  justify-content: center;
  width: 100%;
  height: 100%;
  p {
    ${small} {
      margin-top: 2rem;
      margin-bottom: 4rem;
      width: 75%;
    }
  }
`;

const bgIconStyle = {
  width: '10rem',
  height: '10rem',
};

const customStyle = css`
  height: 100%;
`;

const AwsApplications = (props) => {
  const {
    safeDetail,
    safeData,
    fetchPermission,
    onNewAwsChange,
    newAwsApplication,
    updateToastMessage,
  } = props;

  // const [editGroup, setEditGroup] = useState('');
  // const [editAccess, setEditAccess] = useState('');
  const [response, setResponse] = useState({ status: 'loading' });

  const isMobileScreen = useMediaQuery(small);

  useEffect(() => {
    if (safeData && Object.keys(safeData).length !== 0) {
      if (Object.keys(safeData?.response).length !== 0) {
        setResponse({ status: 'success' });
      } else if (safeData.error !== '') {
        setResponse({ status: 'error' });
      }
    } else {
      setResponse({ status: '' });
    }
  }, [safeData]);

  useEffect(() => {
    if (newAwsApplication) {
      setResponse({ status: 'add' });
    }
  }, [newAwsApplication]);

  const onDeleteClick = (role) => {
    setResponse({ status: 'loading' });
    const payload = {
      path: safeDetail.path,
      role,
    };
    apiService
      .deleteAwsConfiguration(payload)
      .then((res) => {
        if (res && res.data?.messages && res.data?.messages[0]) {
          updateToastMessage(1, res.data.messages[0]);
          setResponse({ status: '' });
          fetchPermission();
        }
      })
      .catch((err) => {
        setResponse({ status: 'success' });
        if (err.response?.data?.errors && err.response.data.errors[0]) {
          updateToastMessage(-1, err.response.data.errors[0]);
        }
      });
  };

  const onSaveClicked = (role, access) => {
    const payload = {
      access,
      path: safeDetail.path,
      role,
    };
    apiService
      .addAwsRole(payload)
      .then((res) => {
        if (res && res.data?.messages) {
          updateToastMessage(1, res.data?.messages[0]);
          setResponse({ status: '' });
          fetchPermission();
        }
      })
      .catch((err) => {
        if (err.response?.data?.errors && err.response.data.errors[0]) {
          updateToastMessage(-1, err.response.data.errors[0]);
        }
        setResponse({ status: 'success' });
      });
  };

  const onSubmit = (data, access) => {
    setResponse({ status: 'loading' });
    onNewAwsChange();
    apiService
      .addAwsConfiguration(`${safeDetail.path}sss`, data)
      .then((res) => {
        updateToastMessage(1, res.data?.messages[0]);
        onSaveClicked(data.role, access);
      })
      .catch((err) => {
        if (err.response?.data?.errors && err.response.data.errors[0]) {
          updateToastMessage(-1, err.response.data.errors[0]);
        }
        setResponse({ status: 'success' });
      });
  };

  // const onEditSaveClicked = (groupname, access) => {
  //   setResponse({ status: 'loading' });
  //   const payload = {
  //     path: `${safeDetail.path}`,
  //     groupname,
  //   };
  //   apiService
  //     .deleteGroup(payload)
  //     .then((res) => {
  //       if (res) {
  //         setResponse({ status: 'loading' });
  //         onSubmit(groupname, access);
  //       }
  //     })
  //     .catch((err) => {
  //       if (err.response?.data?.errors && err.response.data.errors[0]) {
  //         updateToastMessage(-1, err.response.data.errors[0]);
  //       }
  //       setResponse({ status: 'success' });
  //     });
  // };

  const onCancelClicked = () => {
    setResponse({ status: 'success' });
    onNewAwsChange();
  };

  const onEditClick = (key, value) => {
    // setEditAccess(value);
    // setEditGroup(key);
    // setResponse({ status: 'edit' });
    // eslint-disable-next-line no-console
    console.log('key', key);
    // eslint-disable-next-line no-console
    console.log('value', value);
  };

  return (
    <ComponentError>
      <>
        {response.status === 'loading' && (
          <LoaderSpinner customStyle={customStyle} />
        )}
        {response.status === 'add' && (
          <AddAwsApplicationModal
            open
            handleSaveClick={(data, access) => onSubmit(data, access)}
            handleCancelClick={onCancelClicked}
            handleModalClose={() => onCancelClicked()}
          />
        )}

        {/* {response.status === 'edit' && (
          <AddGroup
            handleSaveClick={(group, access) =>
              onEditSaveClicked(group, access)
            }
            handleCancelClick={onCancelClicked}
            groupname={editGroup}
            access={editAccess}
          />
        )} */}
        {safeData &&
          Object.keys(safeData).length > 0 &&
          Object.keys(safeData?.response).length > 0 &&
          response.status !== 'loading' &&
          response.status !== 'error' && (
            <>
              {safeData.response['aws-roles'] &&
                Object.keys(safeData.response['aws-roles']).length > 0 && (
                  <PermissionsList
                    list={safeData.response['aws-roles']}
                    onEditClick={(key, value) => onEditClick(key, value)}
                    onDeleteClick={(key) => onDeleteClick(key)}
                  />
                )}
              {(safeData.response['aws-roles'] === null ||
                !safeData.response['aws-roles'] ||
                (safeData.response['aws-roles'] &&
                  Object.keys(safeData.response['aws-roles']).length ===
                    0)) && (
                <NoDataWrapper>
                  <NoData
                    imageSrc={noPermissionsIcon}
                    description="No applications are given permission to access this safe,
                    add applications to access the safe"
                    actionButton={
                      // eslint-disable-next-line react/jsx-wrap-multilines
                      <ButtonComponent
                        label="add"
                        icon="add"
                        color="secondary"
                        onClick={() => setResponse({ status: 'add' })}
                        width={isMobileScreen ? '100%' : '38%'}
                      />
                    }
                    bgIconStyle={bgIconStyle}
                    width={isMobileScreen ? '100%' : '42%'}
                  />
                </NoDataWrapper>
              )}
            </>
          )}
        {response.status === 'error' && (
          <Error description={safeData.error || 'Something went wrong!'} />
        )}
      </>
    </ComponentError>
  );
};

AwsApplications.propTypes = {
  safeDetail: PropTypes.objectOf(PropTypes.any).isRequired,
  safeData: PropTypes.objectOf(PropTypes.any).isRequired,
  fetchPermission: PropTypes.func.isRequired,
  newAwsApplication: PropTypes.bool.isRequired,
  onNewAwsChange: PropTypes.func.isRequired,
  updateToastMessage: PropTypes.func.isRequired,
};
export default AwsApplications;
