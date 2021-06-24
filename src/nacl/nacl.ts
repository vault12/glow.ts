import { NaClDriver } from './nacl-driver.interface';
import { JsNaClDriver } from './js-nacl-driver';

/**
 * Facade singleton to access the NaCl driver.
 * Usage: call instance() with a chosen driver, and store the received object to perform further actions.
 */
export class NaCl {
  private static driverInstance?: NaClDriver;

  private constructor() { }

  public static setInstance(driver = new JsNaClDriver()): boolean {
    if (this.driverInstance) {
      throw new Error('[NaCl] NaCl driver has been already set, it is supposed to be set only once');
    } else {
      // fallback to the default JS driver
      this.driverInstance = driver;
    }

    return true;
  }

  public static getInstance(): NaClDriver {
    if (!this.driverInstance) {
      throw new Error('[NaCl] NaCl instance is not yet set');
    }

    return this.driverInstance;
  }
}
