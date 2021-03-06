import React, { useCallback, useState } from 'react';
import { Button, Alert, Text, SafeAreaView, Platform } from 'react-native';
import SInfo from '@sampension/react-native-sensitive-info';

const isIOS = Platform.OS === 'ios';

const Home: React.FC = () => {
  const handleAddUsingSetItemOnPress = useCallback(() => {
    SInfo.setItem('key1', 'value1', {
      sharedPreferencesName: 'exampleApp',
      keychainService: 'exampleApp',
    });
  }, []);

  const handleReadingDataWithoutFingerprint = useCallback(async () => {
    const data = await SInfo.getItem('key1', {
      sharedPreferencesName: 'exampleApp',
      keychainService: 'exampleApp',
    });

    Alert.alert('Data stored:', data);
  }, []);

  const handleSetItemUsingTouchIDOnPress = useCallback(async () => {
    try {
      const deviceHasSensor = await SInfo.isSensorAvailable();

      if (!deviceHasSensor) {
        return Alert.alert('No sensor found');
      }

      const data = await SInfo.setItem(
        'touchIdItem',
        new Date().toISOString(),
        {
          sharedPreferencesName: 'exampleApp',
          keychainService: 'exampleApp',
          kSecAttrAccessible: 'kSecAttrAccessibleWhenUnlockedThisDeviceOnly',
          kSecAttrSynchronizable: false,
          /*
           NOTE: These options offer way more in terms of security, but we are not using
           them because it will prompt for biometrics twice during OAuth token refresh flow
          */
          // kSecAccessControl: 'kSecAccessControlBiometryCurrentSet'
          touchID: !isIOS,
          showModal: !isIOS,
        },
      );

      Alert.alert('data successfully stored', data || '');
    } catch (ex) {
      Alert.alert('Error', ex.message);
    }
  }, []);

  const hasTouchIDItem = useCallback(async () => {
    try {
      const hasItem = await SInfo.hasItem('touchIdItem', {
        sharedPreferencesName: 'exampleApp',
        keychainService: 'exampleApp',
        kSecAccessControl: 'kSecAccessControlBiometryAny', // Enabling FaceID
        touchID: true,
        showModal: true,
      });

      Alert.alert(hasItem ? 'Item is present' : 'item is not present');
    } catch (ex) {
      Alert.alert('Error', ex.message);
    }
  }, []);

  const hasPinCodeSet = useCallback(async () => {
    try {
      const hasPin = await SInfo.hasPinCode();

      Alert.alert(hasPin ? 'Pin is set' : 'Pin is not set');
    } catch (ex) {
      Alert.alert('Error', ex.message);
    }
  }, []);

  const getTouchIDItem = useCallback(async () => {
    const deviceHasSensor = await SInfo.isSensorAvailable();

    if (!deviceHasSensor) {
      return Alert.alert('No sensor found');
    }

    try {
      const data = await SInfo.getItem('touchIdItem', {
        sharedPreferencesName: 'exampleApp',
        keychainService: 'exampleApp',
        touchID: true,
        showModal: true,
        strings: {
          description: 'Custom Title ',
          header: 'Custom Description',
        },
        kSecUseOperationPrompt:
          'We need your permission to retrieve encrypted data',
        kLocalizedFallbackTitle: 'Please provide a passcode',
      });

      Alert.alert('Data stored', data);
    } catch (ex) {
      console.log(ex);
      Alert.alert('Error', ex.message);
    }
  }, []);

  const removeTouchIDItem = useCallback(async () => {
    const deviceHasSensor = await SInfo.isSensorAvailable();

    if (!deviceHasSensor) {
      return Alert.alert('No sensor found');
    }

    try {
      const data = await SInfo.deleteItem('touchIdItem', {
        sharedPreferencesName: 'exampleApp',
        keychainService: 'exampleApp',
      });

      Alert.alert('Item removed');
    } catch (ex) {
      Alert.alert('Error', ex.message);
    }
  }, []);

  const [logText, setLogText] = useState('');
  async function runTest() {
    const options = {
      sharedPreferencesName: 'exampleAppTest',
      keychainService: 'exampleAppTest',
    };
    let dbgText = '';
    dbgText += `setItem(key1, value1): ${await SInfo.setItem(
      'key1',
      'value1',
      options,
    )}\n`;
    dbgText += `setItem(key2, value2): ${await SInfo.setItem(
      'key2',
      'value2',
      options,
    )}\n`;
    dbgText += `setItem(key3, value3): ${await SInfo.setItem(
      'key3',
      'value3',
      options,
    )}\n`;
    dbgText += `getItem(key2): ${await SInfo.getItem('key2', options)}\n`;
    dbgText += `delItem(key2): ${await SInfo.deleteItem('key2', options)}\n`;
    dbgText += `getAllItems():\n`;
    const allItems = await SInfo.getAllItems(options);
    for (const key in allItems) {
      dbgText += ` - ${key} : ${allItems[key]}\n`;
    }
    setLogText(dbgText);
  }
  runTest();

  return (
    <SafeAreaView style={{ margin: 10 }}>
      <Button
        title="Add item using setItem"
        onPress={handleAddUsingSetItemOnPress}
      />
      <Button
        title="Read data without fingerprint"
        onPress={handleReadingDataWithoutFingerprint}
      />
      <Button
        title="Add item using TouchID"
        onPress={handleSetItemUsingTouchIDOnPress}
      />
      <Button title="Get TouchID Data" onPress={getTouchIDItem} />
      <Button title="Has TouchID Data" onPress={hasTouchIDItem} />
      <Button title="Has PinCode Set" onPress={hasPinCodeSet} />
      <Button title="Remove TouchID Data" onPress={removeTouchIDItem} />
      <Text>{logText}</Text>
    </SafeAreaView>
  );
};
export default Home;
