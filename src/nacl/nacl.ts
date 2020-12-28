import { NaClDriver } from './nacl-driver.interface';
import { JsNaClDriver } from './js-nacl-driver';

/**
 * Facade singleton to access the NaCl driver.
 * Usage: call instance() with a chosen driver, and store the received object to perform further actions.
 */
export class NaCl {
  private static driverInstance?: NaClDriver;

  public static setInstance(driver?: NaClDriver): boolean {
    if (!this.driverInstance) {
      // fallback to the default JS driver
      this.driverInstance = driver || new JsNaClDriver();
    }

    return true;
  }

  public static getInstance(): NaClDriver {
    if (!this.driverInstance) {
      throw new Error('NaCl instance is not yet set');
    }

    return this.driverInstance;
  }
}
